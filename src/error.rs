//! Error types for the DKLs23 protocol.
//!
//! Follows the pattern from the `round-based` random-generation example,
//! parameterized by the MPC engine's send/receive error types.

use alloc::vec::Vec;
use round_based::MsgId;

/// Keygen protocol error.
#[derive(Debug, thiserror::Error)]
pub enum KeygenError<RecvErr, SendErr> {
    /// Failed to send a message in round 1.
    #[error("send message at round 1")]
    Round1Send(#[source] SendErr),
    /// Failed to receive messages in round 1.
    #[error("receive messages at round 1")]
    Round1Receive(#[source] RecvErr),
    /// Failed to send a message in round 2.
    #[error("send message at round 2")]
    Round2Send(#[source] SendErr),
    /// Failed to receive messages in round 2.
    #[error("receive messages at round 2")]
    Round2Receive(#[source] RecvErr),
    /// Failed to send a message in round 3.
    #[error("send message at round 3")]
    Round3Send(#[source] SendErr),
    /// Failed to receive messages in round 3.
    #[error("receive messages at round 3")]
    Round3Receive(#[source] RecvErr),
    /// A party's decommitment didn't match their commitment.
    #[error("decommitment mismatch from parties: {guilty_parties:?}")]
    InvalidDecommitment {
        /// Parties that cheated.
        guilty_parties: Vec<KeygenBlame>,
    },
    /// Feldman verification failed: a party's share is inconsistent.
    #[error("Feldman verification failed for parties: {parties:?}")]
    FeldmanVerificationFailed {
        /// Parties whose shares failed verification.
        parties: Vec<u16>,
    },
    /// The resulting public key is the point at infinity (negligible probability).
    #[error("resulting public key is zero")]
    ZeroPublicKey,
}

/// Blame information for keygen abort.
#[derive(Debug)]
pub struct KeygenBlame {
    /// Index of the guilty party.
    pub guilty_party: u16,
    /// Message ID of the commitment.
    pub commitment_msg: MsgId,
    /// Message ID of the decommitment.
    pub decommitment_msg: MsgId,
}

/// Signing protocol error.
#[derive(Debug, thiserror::Error)]
pub enum SignError<RecvErr, SendErr> {
    /// Failed to send a message in round 1.
    #[error("send message at sign round 1")]
    Round1Send(#[source] SendErr),
    /// Failed to receive messages in round 1.
    #[error("receive messages at sign round 1")]
    Round1Receive(#[source] RecvErr),
    /// Failed to send a message in round 2.
    #[error("send message at sign round 2")]
    Round2Send(#[source] SendErr),
    /// Failed to receive messages in round 2.
    #[error("receive messages at sign round 2")]
    Round2Receive(#[source] RecvErr),
    /// Failed to send a message in round 3.
    #[error("send message at sign round 3")]
    Round3Send(#[source] SendErr),
    /// Failed to receive messages in round 3.
    #[error("receive messages at sign round 3")]
    Round3Receive(#[source] RecvErr),
    /// Consistency check failed (§3.2 step 8 of DKLs23).
    #[error("consistency check failed for party {party}")]
    ConsistencyCheckFailed {
        /// Index of the party that failed the check.
        party: u16,
    },
    /// Public key shares don't sum to the expected public key.
    #[error("public key shares inconsistent")]
    PublicKeyMismatch,
    /// The assembled signature failed ECDSA verification.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// Nonce point R is the point at infinity (negligible probability).
    #[error("nonce R is zero")]
    ZeroNonce,
}

/// Keygen error type deduced from `M: Mpc`.
pub type KeygenErrorM<M> = KeygenError<
    round_based::mpc::CompleteRoundErr<M, round_based::round::RoundInputError>,
    <M as round_based::Mpc>::SendErr,
>;

/// Sign error type deduced from `M: Mpc`.
pub type SignErrorM<M> = SignError<
    round_based::mpc::CompleteRoundErr<M, round_based::round::RoundInputError>,
    <M as round_based::Mpc>::SendErr,
>;
