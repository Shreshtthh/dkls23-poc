//! Key generation message types.
//!
//! # Paper Reference
//! Protocol 7.1 (πRelaxedKeyGen): commit-release-verify.

use alloc::vec::Vec;
use generic_ec::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};

/// Protocol message enum for key generation.
#[derive(round_based::ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Round2Msg<E>: Serialize",
    deserialize = "Round2Msg<E>: Deserialize<'de>"
))]
pub enum Msg<E: Curve> {
    /// Round 1: blinding commitment.
    Round1(Round1Msg),
    /// Round 2: reveal public polynomial + Shamir shares.
    Round2(Round2Msg<E>),
    /// Round 3: ok/abort.
    Round3(Round3Msg),
}

/// Round 1: a blinding-factor commitment.
///
/// We commit to a random 32-byte nonce. The decommitment in Round 2
/// reveals the nonce alongside the actual data, and verifiers check
/// `SHA256(nonce) == commitment`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Msg {
    /// `SHA256(blinding_factor)`.
    pub commitment: [u8; 32],
}

/// Round 2: decommitment + polynomial coefficients + Shamir shares.
///
/// # Paper Reference
/// Protocol 7.1, steps 2-3.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Point<E>: Serialize, ShareEval<E>: Serialize",
    deserialize = "Point<E>: Deserialize<'de>, ShareEval<E>: Deserialize<'de>"
))]
pub struct Round2Msg<E: Curve> {
    /// The blinding factor whose hash was committed in Round 1.
    pub blinding_factor: [u8; 32],
    /// Public polynomial coefficients: `Pᵢ(k) = pᵢ(k) · G` for k ∈ [0, t-1].
    pub public_coefficients: Vec<Point<E>>,
    /// Shamir share evaluations for each other party.
    pub share_evaluations: Vec<ShareEval<E>>,
}

/// A Shamir share evaluation `pᵢ(j+1)` from party i to party j.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Scalar<E>: Serialize",
    deserialize = "Scalar<E>: Deserialize<'de>"
))]
pub struct ShareEval<E: Curve> {
    /// Recipient party index (0-indexed).
    pub recipient: u16,
    /// The scalar value `pᵢ(j+1)`.
    pub value: Scalar<E>,
}

/// Round 3: ok/abort after Feldman verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Msg {
    /// Whether this party's verification passed.
    pub ok: bool,
}
