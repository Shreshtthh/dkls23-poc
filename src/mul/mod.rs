//! Ideal two-party multiplication (VOLE) functionality.
//!
//! # Paper Reference
//! - Functionality 3.4 (F_RVOLE): Random Vector OLE
//! - Section 5: Random Vector OLE from Random OT
//!
//! # POC Approach
//!
//! In the full DKLs23 protocol, RVOLE is an interactive sub-protocol
//! based on Oblivious Transfer. For this POC, we simulate F_RVOLE as
//! a **trusted dealer** that pre-computes all correlated shares before
//! the signing protocol begins.
//!
//! This mirrors the paper's own proof strategy: Protocol 3.6 is proven
//! secure *assuming* an ideal F_RVOLE. Our POC instantiates that ideal
//! functionality directly, clearly delineating where the OT-based
//! construction (§5) would plug in for production.

use alloc::vec::Vec;
use generic_ec::{Curve, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

use crate::key_share::KeyShare;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Pre-computed signing correlation for a single party.
///
/// Produced by [`trusted_dealer`], which simulates F_RVOLE by computing
/// all cross-party products with full knowledge of every party's secrets.
#[derive(Clone, Debug)]
pub struct SigningCorrelation<E: Curve> {
    /// This party's nonce share: rᵢ
    pub nonce_share: SecretScalar<E>,
    /// This party's inversion mask: ϕᵢ
    pub inversion_mask: SecretScalar<E>,
    /// Pairwise RVOLE output for each counterparty.
    pub pairs: Vec<PairwiseShares<E>>,
}

/// Additive shares of cross-party products between this party and one
/// counterparty, as produced by the ideal F_RVOLE.
///
/// Given parties i (self) and j (counterparty):
/// - `cu + (j's du)  = rᵢ · ϕⱼ`   (this party is "sender")
/// - `du + (j's cu)  = rⱼ · ϕᵢ`   (this party is "receiver")
///
/// Same pattern for `cv`/`dv` with `sk` in place of `r`.
#[derive(Clone, Debug)]
pub struct PairwiseShares<E: Curve> {
    /// Counterparty index.
    pub counterparty: u16,
    /// This party's additive share of `rᵢ · ϕⱼ` (sender role).
    pub cu: Scalar<E>,
    /// This party's additive share of `skᵢ · ϕⱼ` (sender role).
    pub cv: Scalar<E>,
    /// This party's additive share of `rⱼ · ϕᵢ` (receiver role).
    pub du: Scalar<E>,
    /// This party's additive share of `skⱼ · ϕᵢ` (receiver role).
    pub dv: Scalar<E>,
}

// ---------------------------------------------------------------------------
// Trusted dealer (ideal F_RVOLE simulation)
// ---------------------------------------------------------------------------

/// Simulates the ideal F_RVOLE by pre-computing all signing correlations.
///
/// The dealer has access to **all** parties' secrets — this is intentional
/// and matches the ideal-world definition in the paper. In production,
/// this would be replaced by the interactive OT-based RVOLE (§5).
///
/// # Arguments
/// * `key_shares` — All parties' key shares (indexed by party id).
/// * `signers`    — Indices of the parties participating in signing.
/// * `rng`        — Cryptographically secure RNG.
///
/// # Returns
/// One [`SigningCorrelation`] per signer, in the same order as `signers`.
pub fn trusted_dealer<E: Curve, R: RngCore + CryptoRng>(
    key_shares: &[KeyShare<E>],
    signers: &[u16],
    rng: &mut R,
) -> Vec<SigningCorrelation<E>> {
    let n = signers.len();

    // 1. Sample nonces and inversion masks for every party.
    let r: Vec<SecretScalar<E>> = (0..n).map(|_| SecretScalar::<E>::random(rng)).collect();
    let phi: Vec<SecretScalar<E>> = (0..n).map(|_| SecretScalar::<E>::random(rng)).collect();

    // 2. Compute each signer's additive secret-key share via Lagrange.
    let sk: Vec<Scalar<E>> = signers
        .iter()
        .map(|&party_i| {
            let lc = lagrange_coefficient::<E>(signers, party_i);
            *key_shares[party_i as usize].secret_share.as_ref() * lc
        })
        .collect();

    // 3. For each ordered pair (i, j), split the cross-products
    //    rᵢ·ϕⱼ  and  skᵢ·ϕⱼ  into random additive shares.
    //
    //    Party i gets  cᵤ  (sender share)
    //    Party j gets  dᵤ = product − cᵤ  (receiver share)
    //
    //    We store these in a matrix so we can distribute them.
    //    sender_shares[i][j] = (cu, cv)  — party i's sender share for pair (i,j)
    //    The corresponding receiver share for party j is (product - cu, product - cv).

    // sender_cu[i][j], sender_cv[i][j]
    let mut sender_cu: Vec<Vec<Scalar<E>>> = Vec::with_capacity(n);
    let mut sender_cv: Vec<Vec<Scalar<E>>> = Vec::with_capacity(n);

    #[allow(clippy::needless_range_loop)]
    for idx_i in 0..n {
        let mut row_cu = Vec::with_capacity(n);
        let mut row_cv = Vec::with_capacity(n);
        for idx_j in 0..n {
            if idx_i == idx_j {
                row_cu.push(Scalar::<E>::zero());
                row_cv.push(Scalar::<E>::zero());
                continue;
            }
            // Products: rᵢ · ϕⱼ  and  skᵢ · ϕⱼ
            let r_i_phi_j: Scalar<E> = *r[idx_i].as_ref() * phi[idx_j].as_ref();
            let sk_i_phi_j: Scalar<E> = sk[idx_i] * phi[idx_j].as_ref();

            // Random sender shares
            let cu = *SecretScalar::<E>::random(rng).as_ref();
            let cv = *SecretScalar::<E>::random(rng).as_ref();

            // Verify: receiver share = product - sender share
            let _du = r_i_phi_j - cu;
            let _dv = sk_i_phi_j - cv;

            row_cu.push(cu);
            row_cv.push(cv);
        }
        sender_cu.push(row_cu);
        sender_cv.push(row_cv);
    }

    // 4. Assemble per-party correlations.
    (0..n)
        .map(|idx_i| {
            let pairs = (0..n)
                .filter(|&idx_j| idx_j != idx_i)
                .map(|idx_j| {
                    // --- This party (i) as SENDER to party j ---
                    // Product: rᵢ · ϕⱼ = sender_cu[i][j] + receiver_du_for_j
                    let cu = sender_cu[idx_i][idx_j];
                    let cv = sender_cv[idx_i][idx_j];

                    // --- This party (i) as RECEIVER from party j ---
                    // Product: rⱼ · ϕᵢ = sender_cu[j][i] + du
                    // du = rⱼ · ϕᵢ − sender_cu[j][i]
                    let r_j_phi_i: Scalar<E> = *r[idx_j].as_ref() * phi[idx_i].as_ref();
                    let du = r_j_phi_i - sender_cu[idx_j][idx_i];

                    let sk_j_phi_i: Scalar<E> = sk[idx_j] * phi[idx_i].as_ref();
                    let dv = sk_j_phi_i - sender_cv[idx_j][idx_i];

                    PairwiseShares {
                        counterparty: signers[idx_j],
                        cu,
                        cv,
                        du,
                        dv,
                    }
                })
                .collect();

            SigningCorrelation {
                nonce_share: r[idx_i].clone(),
                inversion_mask: phi[idx_i].clone(),
                pairs,
            }
        })
        .collect()
}

/// Lagrange coefficient for party `i` in `signers`, evaluated at x = 0.
pub fn lagrange_coefficient<E: Curve>(signers: &[u16], i: u16) -> Scalar<E> {
    let x_i = Scalar::<E>::from(i as u64 + 1);
    let mut coeff = Scalar::<E>::one();
    for &j in signers {
        if j == i {
            continue;
        }
        let x_j = Scalar::<E>::from(j as u64 + 1);
        coeff = coeff * (-x_j) * (x_i - x_j).invert().expect("distinct signers");
    }
    coeff
}
