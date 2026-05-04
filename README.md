# DKLs23 - Threshold ECDSA in Three Rounds

A proof-of-concept Rust implementation of the **DKLs23** threshold ECDSA protocol, built on the [Lockness](https://github.com/LFDT-Lockness) ecosystem's [`round-based`](https://github.com/LFDT-Lockness/round-based) framework and [`generic-ec`](https://github.com/LFDT-Lockness/generic-ec) library.

> **Paper:** Doerner, Kondi, Lee, shelat - *"Threshold ECDSA in Three Rounds"*
> [ePrint 2023/765](https://eprint.iacr.org/2023/765)

---

## Motivation

In standard ECDSA, a single compromised private key means total failure. **Threshold Signing Schemes (TSS)** mitigate this by distributing key shares across `n` participants, requiring a minimum threshold `t` to collaboratively produce a signature - without ever reconstructing the full private key.

DKLs23 achieves threshold ECDSA in just **three rounds** of communication, offering a compelling alternative to existing protocols like CGGMP24 (already implemented in the Lockness ecosystem). This POC demonstrates the protocol's core mechanics, validates mathematical correctness through end-to-end tests, and establishes the foundation for a production-grade implementation.

---

## What This POC Proves

```
┌─────────────────────────────────────────────────────────────────┐
│                    End-to-End Test Flow                         │
│                                                                 │
│  Party 0 ──┐                                     ┌── Party 0    │
│            ├── KeyGen (Protocol 7.1) ──► shares ─┤              │
│  Party 1 ──┘                                     └── Party 1    │
│                                                                 │
│  Trusted Dealer ──► F_RVOLE correlations (Functionality 3.4)    │
│                                                                 │
│  Party 0 ──┐                                    ┌── Party 0     │
│            ├── Sign (Protocol 3.6) ──► (r, s) ──┤               │
│  Party 1 ──┘                                    └── Party 1     │
│                                                                 │
│  Standard ECDSA Verify(pk, H(m), σ) ══►  VALID                 
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

The test suite executes a complete **2-of-2 threshold ECDSA** flow:

1. **Distributed Key Generation** - Two parties jointly generate a secp256k1 key pair using Feldman VSS, agreeing on a shared public key while each holding only a Shamir share of the secret.
2. **Threshold Signing** - The same two parties collaboratively sign a message, each contributing a signature fragment computed from their secret share and pre-computed RVOLE correlations.
3. **Standard Verification** - The resulting `(r, s)` signature is verified using textbook ECDSA verification against the joint public key, proving that the MPC protocol produces a standard-compliant signature.

---

## Paper-to-Code Mapping

Every module in this crate maps directly to a specific section of the DKLs23 paper. The table below provides a precise reference for evaluators.

| Paper Section | Protocol / Functionality | Crate Module | Status |
|---|---|---|---|
| §7, Protocol 7.1 | πRelaxedKeyGen (Relaxed Threshold Key Generation) | [`src/keygen/`](src/keygen/) | Implemented |
| §3.2, Protocol 3.6 | πECDSA (Three-Round Signing) | [`src/sign/`](src/sign/) | Implemented |
| §3.1, Functionality 3.4 | F_RVOLE (Random Vector OLE) | [`src/mul/`](src/mul/) | Ideal simulation |
| §2.1, Algorithm 2.3 | ECDSAVerify | [`src/sign/mod.rs`](src/sign/mod.rs#verify_signature) | Implemented |
| §5 | RVOLE from Random OT (SoftSpokenOT) | - | Production target |

### Key Generation - Protocol 7.1 (πRelaxedKeyGen)

**File:** [`src/keygen/mod.rs`](src/keygen/mod.rs)

The "relaxed" key generation avoids expensive zero-knowledge proofs by using a **commit-release-verify** paradigm:

| Protocol Step | Paper Description | Implementation |
|---|---|---|
| Step 1 | Each Pᵢ samples degree-(t-1) polynomial pᵢ(x) | `SecretScalar::random()` for each coefficient |
| Step 2 | Pᵢ commits to public coefficients | SHA-256 blinding-factor commitment |
| Step 3 | Pᵢ decommits, reveals coefficients + Shamir evaluations pᵢ(j) | `Round2Msg` with `public_coefficients` and `share_evaluations` |
| Step 4 | Feldman verification: pⱼ(i)·G =? Pⱼ(i) | `evaluate_public_polynomial_coeffs()` comparison |
| Step 5 | Output (pk, p(i)) where pk = P(0) and p(i) = Σⱼ pⱼ(i) | `KeyShare { public_key, secret_share }` |

**Design choice:** We use SHA-256 blinding-factor commitments instead of hash-of-point commitments. This avoids curve point serialization complexity while providing equivalent binding and hiding properties for the POC.

### Signing - Protocol 3.6 (πECDSA)

**File:** [`src/sign/mod.rs`](src/sign/mod.rs)

The DKLs23 signing protocol rewrites the ECDSA equation `s = k⁻¹(H(m) + rₓ·sk)` into an MPC-friendly form that avoids computing `k⁻¹` directly:

```
s = w / u

where:
  u = Σᵢ uᵢ  →  evaluates to  k · Φ
  w = Σᵢ wᵢ  →  evaluates to  (H(m) + rₓ·sk) · Φ

The inversion mask Φ cancels: s = (H(m) + rₓ·sk) / k = k⁻¹(H(m) + rₓ·sk)
```

Each party computes its fragments using local secrets and RVOLE correlations:

| Protocol Step | Paper Description | Implementation |
|---|---|---|
| Step 5 | Sample nonce rᵢ, inversion mask ϕᵢ | Provided by `SigningCorrelation` (from F_RVOLE dealer) |
| Step 6 | Commit to Rᵢ = rᵢ·G | SHA-256 blinding commitment via `Round1Msg` |
| Step 7 | Decommit Rᵢ, run F_RVOLE, send check-adjust data | `Round2Msg` (RVOLE pre-computed; check-adjust omitted - see [Assumptions](#assumptions)) |
| Step 8 | Verify consistency, compute (wᵢ, uᵢ) | Fragment computation using `correlation.pairs` |
| Step 10 | Assemble s = (Σwᵢ)/(Σuᵢ), verify signature | `verify_signature()` before output |

**Fragment equations (directly from §3.2):**

```rust
// Local (diagonal) products
uᵢ = rᵢ · ϕᵢ

// Cross-party products from RVOLE (Σⱼ for all counterparties j)
uᵢ += Σⱼ (cuᵢⱼ + duᵢⱼ)    // cuᵢⱼ: sender share of rᵢ·ϕⱼ
                              // duᵢⱼ: receiver share of rⱼ·ϕᵢ

// Same pattern for v (with sk replacing r)
vᵢ = skᵢ · ϕᵢ + Σⱼ (cvᵢⱼ + dvᵢⱼ)

// Signature fragment
wᵢ = H(m) · ϕᵢ + rₓ · vᵢ
```

**Correctness proof sketch:**

```
Σᵢ uᵢ = Σᵢ [rᵢ·ϕᵢ + Σⱼ(cuᵢⱼ + duᵢⱼ)]
       = Σᵢ rᵢ·ϕᵢ + Σᵢ Σⱼ rᵢ·ϕⱼ      (cu + du = rᵢ·ϕⱼ by RVOLE guarantee)
       = Σᵢ rᵢ · Σⱼ ϕⱼ                  (factoring)
       = k · Φ                            ✓

Σᵢ wᵢ = Σᵢ [H(m)·ϕᵢ + rₓ·vᵢ]
       = H(m)·Φ + rₓ·sk·Φ
       = (H(m) + rₓ·sk) · Φ              ✓

s = w/u = (H(m) + rₓ·sk)·Φ / (k·Φ) = k⁻¹(H(m) + rₓ·sk)  ✓
```

### Ideal F_RVOLE - Functionality 3.4

**File:** [`src/mul/mod.rs`](src/mul/mod.rs)

The `trusted_dealer()` function simulates the ideal Random Vector OLE functionality. It has access to all parties' secrets and pre-computes the correlated additive shares that would normally be produced by the interactive OT-based protocol.

```rust
// For each pair (i, j), the dealer computes:
//   product = rᵢ · ϕⱼ
//   cu = random()              // party i's sender share
//   du = product - cu          // party j's receiver share
//
// Guarantee: cu + du = rᵢ · ϕⱼ  (for all pairs)
```

---

## Assumptions & Simplifications

This section explicitly documents every simplification made for the POC, and what the production implementation would require.

| Aspect | POC Approach | Production Target | Paper Reference |
|---|---|---|---|
| **F_RVOLE** | Trusted dealer pre-computes all correlations | Interactive OT-based RVOLE (SoftSpokenOT) | §5 |
| **Consistency Check** | Omitted (trusted dealer is correct by construction) | Full check-adjust mechanism with χ, ψ, Γ values | §3.2, Protocol 3.6 step 7-8 |
| **Commitments** | SHA-256 blinding-factor scheme | UC-secure commitment functionality F_Com | §2.2 |
| **Party Count** | Tested with n=t=2 | Arbitrary t-of-n | §7 |
| **Abort Handling** | Protocol returns error on failure | Identifiable abort with blame assignment | §4 |
| **Zero-sharing** | Omitted (not needed for t=n) | Required for t < n threshold signing | Protocol 3.6 step 7 |

### Why Ideal F_RVOLE Is the Right POC Choice

The DKLs23 paper itself uses this exact proof strategy: **Protocol 3.6 is proven secure in the F_RVOLE-hybrid model** (Theorem 3.8). The protocol's correctness is independent of how RVOLE is instantiated - it only requires the RVOLE correlation guarantee (`c + d = a · b`).

By implementing against the ideal functionality, this POC:

1. **Validates the signing equation** - proves the mathematical construction is correctly translated from paper to code
2. **Mirrors the paper's modularity** - the RVOLE is a drop-in black box, exactly as in the security proof
3. **Isolates the protocol logic** - any bugs are in the signing protocol, not in OT/RVOLE implementation details
4. **Establishes the interface** - `SigningCorrelation` defines exactly what the production RVOLE must produce

---

## Architecture

```
dkls23-poc/
├── Cargo.toml              # Lockness ecosystem dependencies
├── src/
│   ├── lib.rs              # Crate root, module tree, #[no_std] support
│   ├── key_share.rs        # KeyShare struct (Shamir share + joint public key)
│   ├── error.rs            # Parameterized error types (KeygenError, SignError)
│   ├── keygen/
│   │   ├── mod.rs          # Protocol 7.1 - commit-release-verify key generation
│   │   └── msg.rs          # KeyGen round messages (Msg, Round1Msg, Round2Msg, Round3Msg)
│   ├── sign/
│   │   ├── mod.rs          # Protocol 3.6 - three-round threshold signing
│   │   └── msg.rs          # Signing round messages
│   └── mul/
│       └── mod.rs          # Functionality 3.4 - ideal F_RVOLE + trusted dealer
└── tests/
    └── protocol.rs         # End-to-end integration tests (KeyGen → Sign → Verify)
```

### Design Principles

- **`#[no_std]` compatible** - The crate uses `alloc` but not `std`, matching the Lockness ecosystem pattern for embedded/WASM targets.
- **Generic over curves** - All protocol logic is parameterized by `E: Curve` via `generic-ec`, enabling use with secp256k1, secp256r1, or any supported curve.
- **`round-based` native** - Uses `Mpc`, `MpcExecution`, `reliable_broadcast`, and `round::broadcast` directly, following the same patterns as `cggmp24-keygen`.
- **Explicit serde bounds** - All message types use `#[serde(bound(serialize = "...", deserialize = "..."))]` to correctly handle the `Curve` trait parameter, matching the Lockness convention.

---

## Ecosystem Integration

This POC is designed to integrate seamlessly with the existing Lockness MPC stack:

| Dependency | Version | Usage |
|---|---|---|
| [`round-based`](https://github.com/LFDT-Lockness/round-based) | `m` branch (v0.5-alpha) | MPC round management, message routing, simulation |
| [`generic-ec`](https://github.com/LFDT-Lockness/generic-ec) | 0.5 | Type-safe elliptic curve arithmetic (`Point`, `Scalar`, `SecretScalar`, `NonZero`) |
| [`generic-ec` / `AlwaysHasAffineX`](https://docs.rs/generic-ec/0.5.0/generic_ec/coords/trait.AlwaysHasAffineX.html) | 0.5 | ECDSA x-coordinate extraction (`R.x().to_scalar()`) |

### API Patterns Borrowed from `cggmp24`

| Pattern | `cggmp24` Reference | Our Usage |
|---|---|---|
| `Mpc<Msg = Msg<E>>` trait bound | `signing.rs:600` | `sign()` function signature |
| `SecretScalar::new(&mut scalar)` | `signing.rs:1415` | Lagrange-interpolated key share conversion |
| `NonZero<Point<E>>: AlwaysHasAffineX<E>` | `signing.rs:426` | X-coordinate extraction for ECDSA |
| `#[serde(bound(...))]` on all generic types | Throughout | All message and data structs |
| `round_based::sim::run_with_setup` | Test patterns | Integration test simulation |

---

## Running

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Check compilation only
cargo check
```

### Expected Output

```
running 2 tests
test keygen_2_of_2 ... ok
test keygen_and_sign_2_of_2 ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

---

## Roadmap: From POC to Production

This POC establishes the protocol skeleton. The following work items represent the path to a production-grade `dkls23` crate within the Lockness ecosystem:

### Phase 1: Interactive RVOLE (§5)
Replace `trusted_dealer` with an interactive OT-based RVOLE protocol:
- Implement SoftSpokenOT (or adapt existing OT libraries)
- Add 2 additional sub-rounds within the signing protocol for OT messages
- Re-enable the consistency check (check-adjust with χ, ψ, Γ values)

### Phase 2: Full Protocol Hardening
- **Identifiable abort** (§4) - When signing fails, identify and blame the cheating party
- **Zero-sharing** - Enable proper t-of-n threshold signing (currently only t-of-t)
- **UC-secure commitments** - Replace SHA-256 blinding with the paper's F_Com
- **Execution IDs** - Add session identifiers for concurrent protocol instances

### Phase 3: Ecosystem Integration
- **Builder API** - Follow `cggmp24`'s `SigningBuilder` pattern for ergonomic configuration
- **State machine mode** - Implement `round_based::state_machine::StateMachine` for synchronous usage
- **HD wallet support** - Additive key derivation (BIP-32 compatible)
- **Benchmarks** - Performance comparison against `cggmp24` signing

---

## References

- **DKLs23 Paper:** Doerner, Kondi, Lee, shelat. *"Threshold ECDSA in Three Rounds."* [ePrint 2023/765](https://eprint.iacr.org/2023/765)
- **CGGMP24 Implementation:** [LFDT-Lockness/cggmp21](https://github.com/LFDT-Lockness/cggmp21) - The existing threshold ECDSA in the Lockness ecosystem
- **round-based Framework:** [LFDT-Lockness/round-based](https://github.com/LFDT-Lockness/round-based) - MPC protocol execution framework
- **generic-ec Library:** [LFDT-Lockness/generic-ec](https://github.com/LFDT-Lockness/generic-ec) - Type-safe elliptic curve arithmetic

---
