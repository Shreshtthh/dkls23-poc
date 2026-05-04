//! Integration tests for the DKLs23 POC.
//!
//! Uses `round_based::sim` to simulate multi-party protocol execution.

use generic_ec::curves::Secp256k1;
use rand::Rng;

use dkls23_poc::keygen;
use dkls23_poc::sign;

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

    // All parties must agree on the same public key
    let pk0 = shares[0].public_key;
    let pk1 = shares[1].public_key;
    assert_eq!(pk0, pk1, "parties must agree on the same public key");

    std::println!("✅ KeyGen 2-of-2: public key agreement verified");
}

/// Test full flow: keygen → sign → verify.
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

    // --- Phase 2: Signing ---
    let message = b"Hello, DKLs23!";
    let message_hash = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(message);
        generic_ec::Scalar::<Secp256k1>::from_be_bytes_mod_order(hash)
    };

    let signers: Vec<u16> = (0..n).collect();

    let signatures = round_based::sim::run_with_setup(
        core::iter::repeat_with(|| rng.fork()).take(n.into()),
        |i, party, rng| {
            let share = shares[i as usize].clone();
            let signers = signers.clone();
            let msg_hash = message_hash;
            async move {
                sign::sign::<Secp256k1, _, _>(
                    party,
                    i,
                    n,
                    &share,
                    &signers,
                    &msg_hash,
                    rng,
                )
                .await
            }
        },
    )
    .unwrap()
    .expect_ok();

    let sig = &signatures[0];
    std::println!("✅ Signing complete. r: {:?}, s: {:?}", sig.r, sig.s);

    // --- Phase 3: Independent Verification ---
    assert!(
        sign::verify_signature::<Secp256k1>(&pk, &message_hash, sig),
        "signature must verify against the joint public key"
    );

    std::println!("✅ Signature verified!");
    std::println!("=== DKLs23 POC: Full flow PASSED ===");
}
