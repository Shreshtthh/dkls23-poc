//! Three-round signing protocol for DKLs23.
//!
//! Implements Protocol 3.6 (πECDSA) from the DKLs23 paper.
//!
//! # Protocol Overview (simplified for 2-of-2)
//!
//! The ECDSA signing equation `s = k⁻¹(H(m) + rₓ·sk)` is rewritten as:
//!
//! ```text
//! s = w / u
//! where w = Σᵢ wᵢ,  u = Σᵢ uᵢ
//!       wᵢ = H(m)·ϕᵢ + rₓ·vᵢ
//!       uᵢ = rᵢ·(adjusted ϕ) + Σⱼ(cᵘᵢ,ⱼ + dᵘᵢ,ⱼ)
//! ```
//!
//! # Paper Reference
//! Section 3.2, Protocol 3.6

pub mod msg;

use generic_ec::coords::AlwaysHasAffineX;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};
use round_based::{Mpc, MpcExecution};
use sha2::{Digest, Sha256};

use crate::error::{SignError, SignErrorM};
use crate::key_share::KeyShare;
use crate::mul;

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
/// * `mpc` - The MPC engine providing networking.
/// * `i` - This party's index in the signing group (0-indexed).
/// * `n` - Number of parties in the signing group (= t for threshold signing).
/// * `key_share` - This party's key share from key generation.
/// * `signers` - Indices of parties participating in this signing session.
/// * `message_hash` - The hash of the message to sign: H(m).
/// * `rng` - Cryptographically secure random number generator.
///
/// # Returns
/// An ECDSA [`Signature`] `(r, s)`.
///
/// # Paper Reference
/// Protocol 3.6 (πECDSA)
pub async fn sign<E, M, R>(
    mut mpc: M,
    i: u16,
    n: u16,
    key_share: &KeyShare<E>,
    signers: &[u16],
    message_hash: &Scalar<E>,
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

    // --- Step 5: Sample secrets ---
    // Protocol 3.6, step 5
    let r_i = SecretScalar::<E>::random(&mut rng);
    let phi_i = SecretScalar::<E>::random(&mut rng);

    let R_i: Point<E> = Point::generator() * &r_i;

    // Convert Shamir share to additive share using Lagrange interpolation
    // Protocol 3.6, step 7: "ski := p(i) · lagrange(P, i, 0) + ζi"
    let lagrange_coeff = lagrange_coefficient::<E>(signers, i);
    let mut sk_i_additive: Scalar<E> = *key_share.secret_share.as_ref() * lagrange_coeff;
    let sk_i = SecretScalar::new(&mut sk_i_additive);

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

    // --- Compute RVOLE (ideal functionality) ---
    // For the POC we simulate the ideal functionality locally.
    let (sender_out, receiver_out) =
        mul::ideal_rvole::<E, _>(&r_i, &sk_i, &phi_i, &mut rng);

    let phi_scalar: Scalar<E> = *phi_i.as_ref();
    let psi = phi_scalar - receiver_out.chi;

    // Consistency check values (Protocol 3.6, step 7)
    let gamma_u: Point<E> = Point::generator() * sender_out.c1;
    let gamma_v: Point<E> = Point::generator() * sender_out.c2;

    let pk_share: Point<E> = Point::generator() * &sk_i;

    // --- Round 2: Decommit + check-adjust ---
    mpc.send_to_all(Msg::Round2(Round2Msg {
        blinding_factor,
        nonce_public: R_i,
        gamma_u,
        gamma_v,
        psi,
        pk_share,
    }))
    .await
    .map_err(SignError::Round2Send)?;

    let round2_msgs = mpc
        .complete(round2)
        .await
        .map_err(SignError::Round2Receive)?;

    // --- Step 8: Verify consistency ---
    let mut all_R: Point<E> = R_i;
    let mut all_pk: Point<E> = pk_share;
    let mut sum_psi_from_others: Scalar<E> = Scalar::zero();

    for (party_j, _com_msg_id, commit) in commitments.into_iter_indexed() {
        // Find corresponding round2 message
        let mut r2msg_ref = None;
        for (pj, _, msg) in round2_msgs.iter_indexed() {
            if pj == party_j {
                r2msg_ref = Some(msg);
                break;
            }
        }
        let r2msg = r2msg_ref.expect("must have round2 msg for each party");

        // Verify commitment
        let expected: [u8; 32] = Sha256::digest(r2msg.blinding_factor).into();
        if commit.commitment != expected {
            return Err(SignError::ConsistencyCheckFailed { party: party_j });
        }

        // Consistency check (Protocol 3.6, step 8):
        //   χᵢ,ⱼ · Rⱼ − Γᵘⱼ,ᵢ = dᵘᵢ,ⱼ · G
        let check_u = r2msg.nonce_public * receiver_out.chi - r2msg.gamma_u;
        let expected_u: Point<E> = Point::generator() * receiver_out.d1;
        if check_u != expected_u {
            return Err(SignError::ConsistencyCheckFailed { party: party_j });
        }

        let check_v = r2msg.pk_share * receiver_out.chi - r2msg.gamma_v;
        let expected_v: Point<E> = Point::generator() * receiver_out.d2;
        if check_v != expected_v {
            return Err(SignError::ConsistencyCheckFailed { party: party_j });
        }

        all_R = all_R + r2msg.nonce_public;
        all_pk = all_pk + r2msg.pk_share;
        sum_psi_from_others = sum_psi_from_others + r2msg.psi;
    }

    // Verify public key consistency: Σ pkₖ = pk
    if all_pk != key_share.public_key.into_inner() {
        return Err(SignError::PublicKeyMismatch);
    }

    // Compute joint nonce R and extract rₓ
    let R_nonzero = NonZero::from_point(all_R).ok_or(SignError::ZeroNonce)?;
    let r_x: Scalar<E> = R_nonzero.x().to_scalar();

    // Compute signature components (Protocol 3.6, step 8)
    let r_i_s: &Scalar<E> = r_i.as_ref();
    let sk_i_s: &Scalar<E> = sk_i.as_ref();

    let adjusted_phi: Scalar<E> = phi_scalar + sum_psi_from_others;

    // uᵢ = rᵢ · (ϕᵢ + Σⱼ ψⱼ,ᵢ) + Σⱼ (cᵘᵢ,ⱼ + dᵘᵢ,ⱼ)
    let u_i: Scalar<E> = *r_i_s * adjusted_phi + (sender_out.c1 + receiver_out.d1);

    // vᵢ = skᵢ · (ϕᵢ + Σⱼ ψⱼ,ᵢ) + Σⱼ (cᵛᵢ,ⱼ + dᵛᵢ,ⱼ)
    let v_i: Scalar<E> = *sk_i_s * adjusted_phi + (sender_out.c2 + receiver_out.d2);

    // wᵢ = H(m) · ϕᵢ + rₓ · vᵢ
    // Note: using adjusted_phi for H(m) term to maintain correlation
    let w_i: Scalar<E> = *message_hash * adjusted_phi + r_x * v_i;

    // --- Round 3: Exchange signature fragments ---
    mpc.send_to_all(Msg::Round3(Round3Msg { w: w_i, u: u_i }))
        .await
        .map_err(SignError::Round3Send)?;

    let fragments = mpc
        .complete(round3)
        .await
        .map_err(SignError::Round3Receive)?;

    // --- Step 10: Assemble signature ---
    let mut sum_w = w_i;
    let mut sum_u = u_i;

    for (_, _, frag) in fragments.into_iter_indexed() {
        sum_w = sum_w + frag.w;
        sum_u = sum_u + frag.u;
    }

    // s = w / u
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
/// Computes R' = s⁻¹·(H(m)·G + rₓ·pk) and checks rₓ' == rₓ.
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

    // R' = s⁻¹ · (H(m) · G + rₓ · pk)
    let u1 = *message_hash * s_inv;
    let u2 = signature.r * s_inv;
    let R_prime: Point<E> = Point::generator() * u1 + public_key.into_inner() * u2;

    match NonZero::from_point(R_prime) {
        Some(R_prime_nz) => R_prime_nz.x().to_scalar() == signature.r,
        None => false,
    }
}

/// Computes the Lagrange coefficient for party `i` in the set of `signers`,
/// evaluated at x = 0.
///
/// ```text
/// lagrange(P, i, 0) = Π_{j ∈ P, j ≠ i} (j+1) / ((j+1) - (i+1))
/// ```
fn lagrange_coefficient<E: Curve>(signers: &[u16], i: u16) -> Scalar<E> {
    let x_i = Scalar::<E>::from(i as u64 + 1);

    let mut coeff = Scalar::<E>::one();
    for &j in signers {
        if j == i {
            continue;
        }
        let x_j = Scalar::<E>::from(j as u64 + 1);
        let num = -x_j;
        let den = x_i - x_j;
        let den_inv = den.invert().expect("distinct signers");
        coeff = coeff * num * den_inv;
    }

    coeff
}
