//! Integration tests for the DKLs23 POC.
//!
//! Uses `round_based::sim` to simulate multi-party protocol execution
//! and `mul::trusted_dealer` to pre-compute ideal F_RVOLE correlations.

use dkls23_poc::keygen;
use dkls23_poc::mul;
use dkls23_poc::sign;
use generic_ec::curves::Secp256k1;

/// Test 2-of-2 key generation produces consistent key shares.
#[test]
fn keygen_2_of_2() {
    let mut rng = rand_dev::DevRng::new();
    let n: u16 = 2;
    let t: u16 = 2;

    let shares = round_based::sim::run_with_setup(
        core::iter::repeat_with(|| rng.fork()).take(n.into()),
        |i, party, rng| keygen::keygen::<Secp256k1, _, _>(party, i, n, t, rng),
    )
    .unwrap()
    .expect_ok();

    let pk0 = shares[0].public_key;
    let pk1 = shares[1].public_key;
    assert_eq!(pk0, pk1, "parties must agree on the same public key");

    std::println!("✅ KeyGen 2-of-2: public key agreement verified");
}

/// Test full flow: keygen → sign → verify.
///
/// This is the ultimate correctness proof: the MPC protocol produces
/// a valid ECDSA signature that verifies against the joint public key.
#[test]
fn keygen_and_sign_2_of_2() {
    let mut rng = rand_dev::DevRng::new();
    let n: u16 = 2;
    let t: u16 = 2;

    // --- Phase 1: Key Generation ---
    let shares = round_based::sim::run_with_setup(
        core::iter::repeat_with(|| rng.fork()).take(n.into()),
        |i, party, rng| keygen::keygen::<Secp256k1, _, _>(party, i, n, t, rng),
    )
    .unwrap()
    .expect_ok();

    let pk = shares[0].public_key;
    std::println!("✅ KeyGen complete. Public key: {:?}", pk);

    // --- Phase 2: Pre-compute ideal F_RVOLE correlations ---
    // The trusted dealer has access to all parties' secrets.
    // In production, this would be replaced by interactive OT-based RVOLE (§5).
    let message = b"Hello, DKLs23!";
    let message_hash = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(message);
        generic_ec::Scalar::<Secp256k1>::from_be_bytes_mod_order(hash)
    };

    let signers: Vec<u16> = (0..n).collect();
    let correlations = mul::trusted_dealer::<Secp256k1, _>(&shares, &signers, &mut rng);

    // --- Phase 3: Signing ---
    let signatures = round_based::sim::run_with_setup(
        core::iter::repeat_with(|| rng.fork()).take(n.into()),
        |i, party, rng| {
            let share = shares[i as usize].clone();
            let signers = signers.clone();
            let msg_hash = message_hash;
            let corr = correlations[i as usize].clone();
            async move {
                sign::sign::<Secp256k1, _, _>(party, i, n, &share, &signers, &msg_hash, &corr, rng)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok();

    let sig = &signatures[0];
    std::println!("✅ Signing complete. r: {:?}, s: {:?}", sig.r, sig.s);

    // --- Phase 4: Independent Verification ---
    assert!(
        sign::verify_signature::<Secp256k1>(&pk, &message_hash, sig),
        "signature must verify against the joint public key"
    );

    std::println!("✅ Signature verified against joint public key!");
    std::println!("=== DKLs23 POC: Full flow (KeyGen → Sign → Verify) PASSED ===");
}
