//! Three-round signing protocol for DKLs23.
//!
//! Implements Protocol 3.6 (πECDSA) from the DKLs23 paper.
//!
//! # Protocol Overview
//!
//! The ECDSA signing equation `s = k⁻¹(H(m) + rₓ·sk)` is rewritten as:
//!
//! ```text
//! s = w / u
//! where  u = Σᵢ uᵢ  =  k · Φ
//!        w = Σᵢ wᵢ  =  (H(m) + rₓ·sk) · Φ
//! ```
//!
//! Each party computes its fragment using:
//! - Local products: `rᵢ·ϕᵢ`, `skᵢ·ϕᵢ`
//! - Cross-party products from F_RVOLE: additive shares of `rⱼ·ϕᵢ`, `skⱼ·ϕᵢ`
//!
//! The Φ cancels in the division, yielding a valid ECDSA signature.
//!
//! # POC Note
//!
//! This implementation accepts pre-computed [`SigningCorrelation`]s
//! produced by [`crate::mul::trusted_dealer`], which simulates the ideal
//! F_RVOLE (Functionality 3.4). In production, these correlations would
//! be generated interactively via OT-based RVOLE (§5).
//!
//! # Paper Reference
//! Section 3.2, Protocol 3.6

pub mod msg;

use generic_ec::coords::AlwaysHasAffineX;
use generic_ec::{Curve, NonZero, Point, Scalar};
use rand_core::{CryptoRng, RngCore};
use round_based::{Mpc, MpcExecution};
use sha2::{Digest, Sha256};

use crate::error::{SignError, SignErrorM};
use crate::key_share::KeyShare;
use crate::mul::SigningCorrelation;

use self::msg::{Msg, Round1Msg, Round2Msg, Round3Msg};

/// An ECDSA signature (r, s).
#[derive(Clone, Debug)]
pub struct Signature<E: Curve> {
    /// The x-coordinate of the nonce point R, reduced modulo q.
    pub r: Scalar<E>,
    /// The signature value s = w/u.
    pub s: Scalar<E>,
}

/// Executes the DKLs23 three-round signing protocol.
///
/// # Arguments
/// * `mpc`          — The MPC engine providing networking.
/// * `i`            — This party's index (0-indexed).
/// * `n`            — Number of signing parties.
/// * `key_share`    — This party's key share from key generation.
/// * `signers`      — Indices of parties participating in signing.
/// * `message_hash` — `H(m)`, the hash of the message to sign.
/// * `correlation`  — Pre-computed RVOLE correlation from [`crate::mul::trusted_dealer`].
/// * `rng`          — Cryptographically secure RNG.
///
/// # Paper Reference
/// Protocol 3.6 (πECDSA)
#[allow(clippy::too_many_arguments)]
pub async fn sign<E, M, R>(
    mut mpc: M,
    i: u16,
    n: u16,
    key_share: &KeyShare<E>,
    signers: &[u16],
    message_hash: &Scalar<E>,
    correlation: &SigningCorrelation<E>,
    mut rng: R,
) -> Result<Signature<E>, SignErrorM<M>>
where
    E: Curve,
    M: Mpc<Msg = Msg<E>>,
    R: RngCore + CryptoRng,
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    // --- Round Setup ---
    let round1 = mpc.add_round(round_based::round::reliable_broadcast::<Round1Msg>(i, n));
    let round2 = mpc.add_round(round_based::round::broadcast::<Round2Msg<E>>(i, n));
    let round3 = mpc.add_round(round_based::round::broadcast::<Round3Msg<E>>(i, n));
    let mut mpc = mpc.finish_setup();

    // --- Step 5: Use pre-computed secrets from the ideal F_RVOLE ---
    let r_i = &correlation.nonce_share;
    let phi_i = &correlation.inversion_mask;

    let R_i: Point<E> = Point::generator() * r_i;

    // Convert Shamir share to additive share via Lagrange interpolation
    let lagrange_coeff = crate::mul::lagrange_coefficient::<E>(signers, i);
    let mut sk_i_additive: Scalar<E> = *key_share.secret_share.as_ref() * lagrange_coeff;
    let sk_i = generic_ec::SecretScalar::new(&mut sk_i_additive);

    let pk_share: Point<E> = Point::generator() * &sk_i;

    // --- Round 1: Commit to nonce ---
    let mut blinding_factor = [0u8; 32];
    rng.fill_bytes(&mut blinding_factor);
    let commitment: [u8; 32] = Sha256::digest(blinding_factor).into();

    mpc.reliably_broadcast(Msg::Round1(Round1Msg { commitment }))
        .await
        .map_err(SignError::Round1Send)?;

    let commitments = mpc
        .complete(round1)
        .await
        .map_err(SignError::Round1Receive)?;

    // --- Round 2: Decommit nonce + pk share ---
    mpc.send_to_all(Msg::Round2(Round2Msg {
        blinding_factor,
        nonce_public: R_i,
        pk_share,
    }))
    .await
    .map_err(SignError::Round2Send)?;

    let round2_msgs = mpc
        .complete(round2)
        .await
        .map_err(SignError::Round2Receive)?;

    // --- Verify commitments and aggregate ---
    let mut all_R: Point<E> = R_i;
    let mut all_pk: Point<E> = pk_share;

    for (party_j, _com_msg_id, commit) in commitments.into_iter_indexed() {
        let mut r2msg_ref = None;
        for (pj, _, msg) in round2_msgs.iter_indexed() {
            if pj == party_j {
                r2msg_ref = Some(msg);
                break;
            }
        }
        let r2msg = r2msg_ref.expect("must have round2 msg for each party");

        // Verify blinding commitment
        let expected: [u8; 32] = Sha256::digest(r2msg.blinding_factor).into();
        if commit.commitment != expected {
            return Err(SignError::ConsistencyCheckFailed { party: party_j });
        }

        all_R += r2msg.nonce_public;
        all_pk += r2msg.pk_share;
    }

    // Verify public key consistency: Σ pkₖ = pk
    if all_pk != key_share.public_key.into_inner() {
        return Err(SignError::PublicKeyMismatch);
    }

    // Compute joint nonce R and extract rₓ
    let R_nonzero = NonZero::from_point(all_R).ok_or(SignError::ZeroNonce)?;
    let r_x: Scalar<E> = R_nonzero.x().to_scalar();

    // --- Compute signature fragments using RVOLE correlations ---
    //
    // From Protocol 3.6 step 8, adapted for ideal F_RVOLE:
    //
    //   uᵢ = rᵢ · ϕᵢ  +  Σⱼ (cuᵢⱼ + duᵢⱼ)
    //   vᵢ = skᵢ · ϕᵢ  +  Σⱼ (cvᵢⱼ + dvᵢⱼ)
    //   wᵢ = H(m) · ϕᵢ  +  rₓ · vᵢ
    //
    // Where cuᵢⱼ is this party's sender share of rᵢ·ϕⱼ,
    //   and duᵢⱼ is this party's receiver share of rⱼ·ϕᵢ.
    //
    // Summing across all parties:
    //   Σ uᵢ = Σᵢ rᵢ·ϕᵢ + Σᵢ Σⱼ (cross terms) = k · Φ  ✓
    //   Σ wᵢ = H(m)·Φ + rₓ·sk·Φ = (H(m) + rₓ·sk)·Φ      ✓

    let r_i_s: &Scalar<E> = r_i.as_ref();
    let sk_i_s: &Scalar<E> = sk_i.as_ref();
    let phi_i_s: &Scalar<E> = phi_i.as_ref();

    // Local (diagonal) products
    let mut u_i: Scalar<E> = *r_i_s * phi_i_s;
    let mut v_i: Scalar<E> = *sk_i_s * phi_i_s;

    // Add cross-party RVOLE shares
    for pair in &correlation.pairs {
        u_i = u_i + pair.cu + pair.du;
        v_i = v_i + pair.cv + pair.dv;
    }

    // wᵢ = H(m) · ϕᵢ + rₓ · vᵢ
    let w_i: Scalar<E> = *message_hash * phi_i_s + r_x * v_i;

    // --- Round 3: Exchange signature fragments ---
    mpc.send_to_all(Msg::Round3(Round3Msg { w: w_i, u: u_i }))
        .await
        .map_err(SignError::Round3Send)?;

    let fragments = mpc
        .complete(round3)
        .await
        .map_err(SignError::Round3Receive)?;

    // --- Step 10: Assemble signature ---
    // s = (Σ wᵢ) / (Σ uᵢ)
    let mut sum_w = w_i;
    let mut sum_u = u_i;

    for (_, _, frag) in fragments.into_iter_indexed() {
        sum_w += frag.w;
        sum_u += frag.u;
    }

    let u_inv = sum_u.invert().ok_or(SignError::ZeroNonce)?;
    let s = sum_w * u_inv;

    let signature = Signature { r: r_x, s };

    // Verify signature before outputting (Protocol 3.6, step 10)
    if !verify_signature::<E>(&key_share.public_key, message_hash, &signature) {
        return Err(SignError::SignatureVerificationFailed);
    }

    Ok(signature)
}

/// Verifies an ECDSA signature.
///
/// Computes `R' = s⁻¹·(H(m)·G + rₓ·pk)` and checks `rₓ' == rₓ`.
pub fn verify_signature<E: Curve>(
    public_key: &NonZero<Point<E>>,
    message_hash: &Scalar<E>,
    signature: &Signature<E>,
) -> bool
where
    NonZero<Point<E>>: AlwaysHasAffineX<E>,
{
    let s_inv = match signature.s.invert() {
        Some(inv) => inv,
        None => return false,
    };

    let u1 = *message_hash * s_inv;
    let u2 = signature.r * s_inv;
    let R_prime: Point<E> = Point::generator() * u1 + public_key.into_inner() * u2;

    match NonZero::from_point(R_prime) {
        Some(nz) => nz.x().to_scalar() == signature.r,
        None => false,
    }
}
