//! Key share types for DKLs23.
//!
//! # Paper Reference
//! Protocol 7.1, step 5: each party outputs `(key-pair, sid, P(0), p(i))`.

use generic_ec::{Curve, NonZero, Point, SecretScalar};
use serde::{Deserialize, Serialize};

/// A party's share of the distributed key.
///
/// Produced by the key generation protocol ([`crate::keygen`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "SecretScalar<E>: Serialize, NonZero<Point<E>>: Serialize",
    deserialize = "SecretScalar<E>: Deserialize<'de>, NonZero<Point<E>>: Deserialize<'de>"
))]
pub struct KeyShare<E: Curve> {
    /// This party's index (0-indexed).
    pub i: u16,
    /// Total number of parties.
    pub n: u16,
    /// Signing threshold.
    pub t: u16,
    /// This party's Shamir share: `p(i) = Σⱼ pⱼ(i)`.
    pub secret_share: SecretScalar<E>,
    /// The joint public key: `pk = P(0)`.
    pub public_key: NonZero<Point<E>>,
}
