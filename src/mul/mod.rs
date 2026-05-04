//! Ideal two-party multiplication (VOLE) functionality.
//!
//! For the POC, we implement the **ideal functionality** (F_RVOLE from
//! Functionality 3.4) as a trusted dealer simulation.
//!
//! # Paper Reference
//! - Functionality 3.4 (F_RVOLE): Random Vector OLE
//! - Section 5: Random Vector OLE from Random OT

use generic_ec::{Curve, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

/// The output of RVOLE for the party that supplies the vector input `(a₁, a₂)`.
#[derive(Clone, Debug)]
pub struct RvoleSenderOutput<E: Curve> {
    /// Share c₁ (corresponds to a₁·b)
    pub c1: Scalar<E>,
    /// Share c₂ (corresponds to a₂·b)
    pub c2: Scalar<E>,
}

/// The output of RVOLE for the party that supplies the single input `b`.
#[derive(Clone, Debug)]
pub struct RvoleReceiverOutput<E: Curve> {
    /// Share d₁ (corresponds to a₁·b - c₁)
    pub d1: Scalar<E>,
    /// Share d₂ (corresponds to a₂·b - c₂)
    pub d2: Scalar<E>,
    /// The random challenge χ sampled by the RVOLE instance.
    pub chi: Scalar<E>,
}

/// Runs the ideal RVOLE functionality as a trusted dealer.
///
/// # Arguments
/// * `a1`, `a2` — The sender's two scalar inputs (e.g., `rⱼ, skⱼ`)
/// * `b` — The receiver's scalar input (e.g., `ϕᵢ`)
/// * `rng` — Random number generator
///
/// # Returns
/// `(sender_output, receiver_output)` such that:
/// - `sender_output.c1 + receiver_output.d1 = a1 · b`
/// - `sender_output.c2 + receiver_output.d2 = a2 · b`
pub fn ideal_rvole<E: Curve, R: RngCore + CryptoRng>(
    a1: &SecretScalar<E>,
    a2: &SecretScalar<E>,
    b: &SecretScalar<E>,
    rng: &mut R,
) -> (RvoleSenderOutput<E>, RvoleReceiverOutput<E>) {
    let a1_s: &Scalar<E> = a1.as_ref();
    let a2_s: &Scalar<E> = a2.as_ref();
    let b_s: &Scalar<E> = b.as_ref();

    // Products that we need additive shares of
    let product1: Scalar<E> = *a1_s * b_s;
    let product2: Scalar<E> = *a2_s * b_s;

    // Sample random sender shares
    let c1_secret = SecretScalar::<E>::random(rng);
    let c2_secret = SecretScalar::<E>::random(rng);
    let c1: Scalar<E> = *c1_secret.as_ref();
    let c2: Scalar<E> = *c2_secret.as_ref();

    // Receiver shares complete the additive decomposition
    let d1 = product1 - c1;
    let d2 = product2 - c2;

    // Sample the random challenge χ
    let chi_secret = SecretScalar::<E>::random(rng);
    let chi: Scalar<E> = *chi_secret.as_ref();

    (
        RvoleSenderOutput { c1, c2 },
        RvoleReceiverOutput { d1, d2, chi },
    )
}
