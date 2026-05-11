//! Key generation protocol for DKLs23.
//!
//! Implements Protocol 7.1 (πRelaxedKeyGen) from the DKLs23 paper.
//!
//! # Protocol Steps (simplified for 2-of-2)
//!
//! 1. Each party Pᵢ samples a random degree-(t-1) polynomial pᵢ over Zq.
//! 2. Pᵢ commits (via blinding hash) to its public polynomial coefficients.
//! 3. Pᵢ decommits, revealing public coefficients and Shamir shares pᵢ(j).
//! 4. Each party verifies Feldman consistency and outputs (pk, p(i)).
//!
//! # Paper Reference
//! Section 7, Protocol 7.1

pub mod msg;

use alloc::vec::Vec;

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};
use round_based::{Mpc, MpcExecution};
use sha2::{Digest, Sha256};

use crate::error::{KeygenBlame, KeygenError, KeygenErrorM};
use crate::key_share::KeyShare;

use self::msg::{Msg, Round1Msg, Round2Msg, Round3Msg, ShareEval};

/// Executes the DKLs23 key generation protocol.
///
/// # Arguments
/// * `mpc` - The MPC engine providing networking.
/// * `i` - This party's index (0-indexed).
/// * `n` - Total number of parties.
/// * `t` - Signing threshold.
/// * `rng` - Cryptographically secure random number generator.
///
/// # Returns
/// A [`KeyShare`] containing this party's Shamir share and the joint public key.
///
/// # Paper Reference
/// Protocol 7.1 (πRelaxedKeyGen)
pub async fn keygen<E, M, R>(
    mut mpc: M,
    i: u16,
    n: u16,
    t: u16,
    mut rng: R,
) -> Result<KeyShare<E>, KeygenErrorM<M>>
where
    E: Curve,
    M: Mpc<Msg = Msg<E>>,
    R: RngCore + CryptoRng,
{
    // --- Round Setup ---
    let round1 = mpc.add_round(round_based::round::reliable_broadcast::<Round1Msg>(i, n));
    let round2 = mpc.add_round(round_based::round::broadcast::<Round2Msg<E>>(i, n));
    let round3 = mpc.add_round(round_based::round::broadcast::<Round3Msg>(i, n));
    let mut mpc = mpc.finish_setup();

    // --- Step 1: Sample random polynomial ---
    // Protocol 7.1, step 1: pᵢ(x) = aᵢ₀ + aᵢ₁·x + ... + aᵢ₍ₜ₋₁₎·xᵗ⁻¹
    let coefficients: Vec<SecretScalar<E>> = (0..t)
        .map(|_| SecretScalar::<E>::random(&mut rng))
        .collect();

    // Public polynomial: Pᵢ(k) = aᵢₖ · G (coefficient form)
    let public_coefficients: Vec<Point<E>> = coefficients
        .iter()
        .map(|c| Point::generator() * c)
        .collect();

    // Evaluate polynomial at each other party's index (using 1-indexed x-values)
    let share_evaluations: Vec<ShareEval<E>> = (0..n)
        .filter(|&j| j != i)
        .map(|j| {
            let x = Scalar::<E>::from(j as u64 + 1);
            let value = evaluate_polynomial(&coefficients, &x);
            ShareEval {
                recipient: j,
                value,
            }
        })
        .collect();

    // --- Round 1: Commit ---
    let mut blinding_factor = [0u8; 32];
    rng.fill_bytes(&mut blinding_factor);
    let commitment: [u8; 32] = Sha256::digest(blinding_factor).into();

    mpc.reliably_broadcast(Msg::Round1(Round1Msg { commitment }))
        .await
        .map_err(KeygenError::Round1Send)?;

    let commitments = mpc
        .complete(round1)
        .await
        .map_err(KeygenError::Round1Receive)?;

    // --- Round 2: Decommit ---
    mpc.send_to_all(Msg::Round2(Round2Msg {
        blinding_factor,
        public_coefficients: public_coefficients.clone(),
        share_evaluations,
    }))
    .await
    .map_err(KeygenError::Round2Send)?;

    let reveals = mpc
        .complete(round2)
        .await
        .map_err(KeygenError::Round2Receive)?;

    // --- Step 4: Verify ---
    let mut guilty_parties = Vec::new();

    // My own share of the secret: starts with p_i(i+1)
    let my_x = Scalar::<E>::from(i as u64 + 1);
    let mut my_share: Scalar<E> = evaluate_polynomial(&coefficients, &my_x);

    // Accumulate joint public polynomial (coefficient form)
    let mut joint_public_coeffs: Vec<Point<E>> = public_coefficients.clone();

    for (party_j, com_msg_id, commit) in commitments.into_iter_indexed() {
        // Find matching reveal from the same party
        let mut found_reveal = None;
        let mut decom_msg_id = com_msg_id; // placeholder
        for (pj, mid, reveal) in reveals.iter_indexed() {
            if pj == party_j {
                found_reveal = Some(reveal);
                decom_msg_id = mid;
                break;
            }
        }
        let reveal = found_reveal.expect("must have reveal for each commitment");

        // Verify blinding commitment
        let expected_commitment: [u8; 32] = Sha256::digest(reveal.blinding_factor).into();
        if commit.commitment != expected_commitment {
            guilty_parties.push(KeygenBlame {
                guilty_party: party_j,
                commitment_msg: com_msg_id,
                decommitment_msg: decom_msg_id,
            });
            continue;
        }

        // Accumulate joint public polynomial
        for (k, coeff) in reveal.public_coefficients.iter().enumerate() {
            if k < joint_public_coeffs.len() {
                joint_public_coeffs[k] += *coeff;
            }
        }

        // Find our share from this party
        if let Some(eval) = reveal.share_evaluations.iter().find(|e| e.recipient == i) {
            // Feldman verification: pⱼ(i+1) · G =? Pⱼ evaluated at (i+1)
            let share_point: Point<E> = Point::generator() * eval.value;
            let expected_point =
                evaluate_public_polynomial_coeffs(&reveal.public_coefficients, &my_x);

            if share_point != expected_point {
                guilty_parties.push(KeygenBlame {
                    guilty_party: party_j,
                    commitment_msg: com_msg_id,
                    decommitment_msg: decom_msg_id,
                });
                continue;
            }

            // Accumulate total Shamir share: p(i) = Σⱼ pⱼ(i)
            my_share += eval.value;
        }
    }

    // --- Round 3: Ok/Abort ---
    let verification_ok = guilty_parties.is_empty();
    mpc.send_to_all(Msg::Round3(Round3Msg {
        ok: verification_ok,
    }))
    .await
    .map_err(KeygenError::Round3Send)?;

    let oks = mpc
        .complete(round3)
        .await
        .map_err(KeygenError::Round3Receive)?;

    if !verification_ok {
        return Err(KeygenError::InvalidDecommitment { guilty_parties });
    }

    // Check if any other party aborted
    let failed_parties: Vec<u16> = oks
        .into_iter_indexed()
        .filter(|(_, _, msg)| !msg.ok)
        .map(|(party, _, _)| party)
        .collect();

    if !failed_parties.is_empty() {
        return Err(KeygenError::FeldmanVerificationFailed {
            parties: failed_parties,
        });
    }

    // --- Compute output ---
    // pk = P(0) = joint_public_coeffs[0] (the constant term)
    let public_key =
        NonZero::from_point(joint_public_coeffs[0]).ok_or(KeygenError::ZeroPublicKey)?;

    let secret_share = SecretScalar::new(&mut my_share);

    Ok(KeyShare {
        i,
        n,
        t,
        secret_share,
        public_key,
    })
}

/// Evaluates a polynomial `p(x) = a₀ + a₁·x + a₂·x² + ...` at point `x`
/// using Horner's method. Coefficients are SecretScalars.
fn evaluate_polynomial<E: Curve>(coefficients: &[SecretScalar<E>], x: &Scalar<E>) -> Scalar<E> {
    let mut result = Scalar::<E>::zero();
    for coeff in coefficients.iter().rev() {
        result = result * x + coeff.as_ref();
    }
    result
}

/// Evaluates a public polynomial in coefficient form at `x`.
/// `P(x) = A₀ + A₁·x + A₂·x² + ...` where each Aₖ is a curve point.
fn evaluate_public_polynomial_coeffs<E: Curve>(
    coefficients: &[Point<E>],
    x: &Scalar<E>,
) -> Point<E> {
    let mut result = Point::<E>::zero();
    for coeff in coefficients.iter().rev() {
        result = result * x + coeff;
    }
    result
}
