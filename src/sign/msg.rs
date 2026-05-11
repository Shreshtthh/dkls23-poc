//! Signing protocol message types for DKLs23.
//!
//! # Paper Reference
//! Protocol 3.6 (πECDSA) — Three-round threshold ECDSA signing.

use generic_ec::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};

/// Protocol message enum for signing.
#[derive(round_based::ProtocolMsg, Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Round2Msg<E>: Serialize, Round3Msg<E>: Serialize",
    deserialize = "Round2Msg<E>: Deserialize<'de>, Round3Msg<E>: Deserialize<'de>"
))]
pub enum Msg<E: Curve> {
    /// Round 1: nonce commitment.
    Round1(Round1Msg),
    /// Round 2: nonce decommitment.
    Round2(Round2Msg<E>),
    /// Round 3: signature fragments.
    Round3(Round3Msg<E>),
}

/// Round 1: blinding commitment to nonce share Rᵢ = rᵢ · G.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Msg {
    /// `SHA256(blinding_factor)`.
    pub commitment: [u8; 32],
}

/// Round 2: nonce decommitment and public key share.
///
/// # Paper Reference
/// Protocol 3.6, step 7 (simplified — consistency check data omitted
/// because the POC uses a pre-computed ideal F_RVOLE).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Point<E>: Serialize",
    deserialize = "Point<E>: Deserialize<'de>"
))]
pub struct Round2Msg<E: Curve> {
    /// Blinding factor for commitment verification.
    pub blinding_factor: [u8; 32],
    /// The nonce share: Rᵢ = rᵢ · G.
    pub nonce_public: Point<E>,
    /// This party's public key share: pkᵢ = skᵢ · G.
    pub pk_share: Point<E>,
}

/// Round 3: signature fragment.
///
/// # Paper Reference
/// Protocol 3.6, step 8.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Scalar<E>: Serialize",
    deserialize = "Scalar<E>: Deserialize<'de>"
))]
pub struct Round3Msg<E: Curve> {
    /// Signature fragment wᵢ = H(m)·ϕᵢ + rₓ·vᵢ.
    pub w: Scalar<E>,
    /// Denominator fragment uᵢ.
    pub u: Scalar<E>,
}
