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
    /// Round 2: nonce decommitment + RVOLE check-adjust data.
    Round2(Round2Msg<E>),
    /// Round 3: signature fragments.
    Round3(Round3Msg<E>),
}

/// Round 1: blinding commitment to nonce share Rᵢ = rᵢ · G.
///
/// # Paper Reference
/// Protocol 3.6, step 6.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Msg {
    /// `SHA256(blinding_factor)`.
    pub commitment: [u8; 32],
}

/// Round 2: nonce decommitment and RVOLE consistency check data.
///
/// # Paper Reference
/// Protocol 3.6, step 7.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Point<E>: Serialize, Scalar<E>: Serialize",
    deserialize = "Point<E>: Deserialize<'de>, Scalar<E>: Deserialize<'de>"
))]
pub struct Round2Msg<E: Curve> {
    /// Blinding factor for commitment verification.
    pub blinding_factor: [u8; 32],
    /// The nonce share: Rᵢ = rᵢ · G.
    pub nonce_public: Point<E>,
    /// Consistency check value: Γᵘᵢ,ⱼ = cᵘᵢ,ⱼ · G.
    pub gamma_u: Point<E>,
    /// Consistency check value: Γᵛᵢ,ⱼ = cᵛᵢ,ⱼ · G.
    pub gamma_v: Point<E>,
    /// Mask adjustment: ψᵢ,ⱼ = ϕᵢ − χᵢ,ⱼ.
    pub psi: Scalar<E>,
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
    /// Signature fragment wᵢ = SHA2(m)·ϕᵢ + rₓ·vᵢ.
    pub w: Scalar<E>,
    /// Denominator fragment uᵢ.
    pub u: Scalar<E>,
}
