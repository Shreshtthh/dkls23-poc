//! # DKLs23 Threshold ECDSA — Proof of Concept
//!
//! A proof-of-concept implementation of the DKLs23 threshold ECDSA protocol
//! ([ePrint 2023/765](https://eprint.iacr.org/2023/765)) using the
//! [`round-based`](https://github.com/LFDT-Lockness/round-based) MPC framework
//! and [`generic-ec`](https://github.com/LFDT-Lockness/generic-ec) for
//! type-safe elliptic curve arithmetic.
//!
//! ## Protocol Overview
//!
//! DKLs23 achieves threshold ECDSA signing in **three rounds** with malicious
//! security against a dishonest majority. Unlike CGGMP-style protocols that use
//! Paillier encryption, DKLs23 is based on **Oblivious Transfer (OT)** via
//! Vector Oblivious Linear Evaluation (VOLE).
//!
//! ### Key Insights
//!
//! 1. **ECDSA Correlation**: The signing equation is rewritten as
//!    `s = w/u` where `w = (H(m) + sk·rₓ)·ϕ` and `u = r·ϕ`, computed
//!    via pairwise VOLE instances.
//!
//! 2. **Statistical Consistency Check**: Rather than zero-knowledge proofs,
//!    DKLs23 uses implicit BeDOZa-style MACs derived from the VOLE outputs
//!    to authenticate inputs (§1.2, §3.2 of the paper).
//!
//! 3. **Relaxed Key Generation**: The key generation protocol (§7) requires
//!    no proofs of knowledge — just commit-release-and-complain.
//!
//! ## Scope
//!
//! This POC implements a simplified **2-of-2** variant to demonstrate the
//! protocol structure, the use of `round-based` and `generic-ec`, and
//! correct ECDSA signature output.
//!
//! | Feature | Status |
//! |---------|--------|
//! | Key Generation (Shamir, 2-of-2) | ✅ Implemented |
//! | Signing (3-round, 2-of-2) | ✅ Implemented |
//! | VOLE / 2P-MUL | ✅ Ideal functionality (simulated) |
//! | Signature Verification | ✅ Standard ECDSA verify |
//! | OT-based VOLE | ❌ Full mentorship scope |
//! | t-of-n generalization | ❌ Full mentorship scope |
//! | Key Refresh | ❌ Full mentorship scope |

#![allow(non_snake_case)]
#![forbid(missing_docs)]
#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod mul;
pub mod sign;
