//! # Lockness Coding Challenge
//!
//! An ECIES-like encryption scheme using `generic-ec` for elliptic curve
//! arithmetic and SHA-256 as the key derivation hash.
//!
//! This is a modification of ECIES (Elliptic Curve Integrated Encryption Scheme)
//! with a simplified KDF (hash-then-repeat). It is known to be insecure.

use generic_ec::{Curve, Point, SecretScalar};
use sha2::{Digest, Sha256};

/// Error type for encryption/decryption operations.
#[derive(Debug)]
pub enum Error {
    /// The ciphertext is too short to contain a valid encoded point.
    CiphertextTooShort,
    /// The encoded point in the ciphertext is invalid.
    InvalidPoint(generic_ec::errors::InvalidPoint),
    /// The shared secret is the point at infinity (ephemeral scalar is zero,
    /// which happens with negligible probability).
    ZeroSharedSecret,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::CiphertextTooShort => write!(f, "ciphertext too short"),
            Error::InvalidPoint(e) => write!(f, "invalid point: {e}"),
            Error::ZeroSharedSecret => write!(f, "shared secret is the point at infinity"),
        }
    }
}

/// Expands a seed byte slice `B` to exactly `len` bytes by repeating it.
///
/// `Expand(B, L)` returns `B || B || ... || B'` where `B'` is a prefix of `B`
/// such that the total length is `L`.
fn expand(seed: &[u8], len: usize) -> Vec<u8> {
    if seed.is_empty() || len == 0 {
        return vec![0u8; len];
    }
    let mut out = Vec::with_capacity(len);
    // Fill with full copies of the seed, then a partial copy for the remainder.
    let full_copies = len / seed.len();
    let remainder = len % seed.len();
    for _ in 0..full_copies {
        out.extend_from_slice(seed);
    }
    out.extend_from_slice(&seed[..remainder]);
    out
}

/// Encrypts a message `M` under public key `pk` on curve `E`.
///
/// ```text
/// Encrypt(pk, M):
///   sample eph <- Z_q
///   let R = G^eph
///   let K = Expand(H(encode(pk^eph)), len(M))
///   let C = M XOR K
///   return encode(R) || C
/// ```
pub fn encrypt<E: Curve>(
    pk: &Point<E>,
    message: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<u8>, Error> {
    // Sample ephemeral scalar
    let eph = SecretScalar::<E>::random(rng);

    // R = G * eph
    let r = Point::<E>::generator() * &eph;
    let r_bytes = r.to_bytes(true);

    // Shared secret = pk * eph
    let shared = pk * &eph;
    if shared.is_zero() {
        return Err(Error::ZeroSharedSecret);
    }
    let shared_bytes = shared.to_bytes(true);

    // K = Expand(SHA256(encode(shared)), len(M))
    let hash = Sha256::digest(shared_bytes.as_bytes());
    let keystream = expand(&hash, message.len());

    // C = M XOR K
    let ciphertext_body: Vec<u8> = message
        .iter()
        .zip(keystream.iter())
        .map(|(m, k)| m ^ k)
        .collect();

    // Output = encode(R) || C
    let mut output = Vec::with_capacity(r_bytes.as_bytes().len() + ciphertext_body.len());
    output.extend_from_slice(r_bytes.as_bytes());
    output.extend_from_slice(&ciphertext_body);
    Ok(output)
}

/// Decrypts a ciphertext produced by [`encrypt`] using the private scalar `sk`.
///
/// The decryption is derived by observing that:
/// - `R = G * eph`, so `R * sk = G * eph * sk = pk * eph` (same shared secret)
/// - The keystream is deterministic given the shared secret
/// - XOR is its own inverse: `M = C XOR K`
///
/// ```text
/// Decrypt(sk, ciphertext):
///   let point_len = serialized_len(compressed)
///   let R = decode(ciphertext[..point_len])
///   let C = ciphertext[point_len..]
///   let K = Expand(H(encode(R^sk)), len(C))
///   let M = C XOR K
///   return M
/// ```
pub fn decrypt<E: Curve>(sk: &SecretScalar<E>, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let point_len = Point::<E>::serialized_len(true);

    if ciphertext.len() < point_len {
        return Err(Error::CiphertextTooShort);
    }

    // Parse R from the first point_len bytes
    let r = Point::<E>::from_bytes(&ciphertext[..point_len]).map_err(Error::InvalidPoint)?;

    let cipher_body = &ciphertext[point_len..];

    // Shared secret = R * sk
    let shared = r * sk;
    if shared.is_zero() {
        return Err(Error::ZeroSharedSecret);
    }
    let shared_bytes = shared.to_bytes(true);

    // K = Expand(SHA256(encode(shared)), len(C))
    let hash = Sha256::digest(shared_bytes.as_bytes());
    let keystream = expand(&hash, cipher_body.len());

    // M = C XOR K
    let plaintext: Vec<u8> = cipher_body
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::Scalar;

    /// Construct a SecretScalar from a u64 value (for test vectors).
    fn secret_scalar_from_u64<E: Curve>(val: u64) -> SecretScalar<E> {
        let mut scalar = Scalar::<E>::from(val);
        SecretScalar::<E>::new(&mut scalar)
    }

    fn run_decrypt_test_vector<E: Curve>(encrypted_hex: &str, expected_hex: &str) {
        let sk = secret_scalar_from_u64::<E>(65537);
        let ciphertext = hex::decode(encrypted_hex).expect("invalid ciphertext hex");
        let expected = hex::decode(expected_hex).expect("invalid expected hex");
        let decrypted = decrypt::<E>(&sk, &ciphertext).expect("decryption failed");
        assert_eq!(
            hex::encode(&decrypted),
            hex::encode(&expected),
            "decrypted message does not match expected"
        );
    }

    // ---- Round-trip tests ----

    #[test]
    fn roundtrip_encrypt_decrypt() {
        use generic_ec::curves::Secp256k1;
        let mut rng = rand::thread_rng();
        let sk = SecretScalar::<Secp256k1>::random(&mut rng);
        let pk = Point::generator() * &sk;
        let message = b"hello lockness challenge!";
        let ct = encrypt(&pk, message, &mut rng).expect("encrypt failed");
        let pt = decrypt(&sk, &ct).expect("decrypt failed");
        assert_eq!(&pt, message);
    }

    #[test]
    fn roundtrip_empty_message() {
        use generic_ec::curves::Secp256k1;
        let mut rng = rand::thread_rng();
        let sk = SecretScalar::<Secp256k1>::random(&mut rng);
        let pk = Point::generator() * &sk;
        let ct = encrypt(&pk, b"", &mut rng).expect("encrypt failed");
        let pt = decrypt(&sk, &ct).expect("decrypt failed");
        assert!(pt.is_empty());
    }

    #[test]
    fn roundtrip_long_message() {
        use generic_ec::curves::Secp256k1;
        let mut rng = rand::thread_rng();
        let sk = SecretScalar::<Secp256k1>::random(&mut rng);
        let pk = Point::generator() * &sk;
        let message = vec![0xABu8; 100];
        let ct = encrypt(&pk, &message, &mut rng).expect("encrypt failed");
        let pt = decrypt(&sk, &ct).expect("decrypt failed");
        assert_eq!(pt, message);
    }

    // ---- ed25519 test vectors (sk = 65537) ----

    #[test]
    fn test_vector_ed25519_1() {
        use generic_ec::curves::Ed25519;
        run_decrypt_test_vector::<Ed25519>(
            "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b16\
             021c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn test_vector_ed25519_2() {
        use generic_ec::curves::Ed25519;
        run_decrypt_test_vector::<Ed25519>(
            "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e575\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
             cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn test_vector_ed25519_3() {
        use generic_ec::curves::Ed25519;
        run_decrypt_test_vector::<Ed25519>(
            "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c\
             6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde\
             433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98\
             067495fdb24b782dac9da5c0eb246c9fb15c00593e",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    // ---- secp256k1 test vectors (sk = 65537) ----

    #[test]
    fn test_vector_secp256k1_1() {
        use generic_ec::curves::Secp256k1;
        run_decrypt_test_vector::<Secp256k1>(
            "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad49\
             40c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395f1",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn test_vector_secp256k1_2() {
        use generic_ec::curves::Secp256k1;
        run_decrypt_test_vector::<Secp256k1>(
            "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d066\
             0ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf6\
             0ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf6\
             0ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf6\
             0ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf6",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn test_vector_secp256k1_3() {
        use generic_ec::curves::Secp256k1;
        run_decrypt_test_vector::<Secp256k1>(
            "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd75879\
             5f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661\
             a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24\
             e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    // ---- secp384r1 test vectors (sk = 65537) ----

    #[test]
    fn test_vector_secp384r1_1() {
        use generic_ec::curves::Secp384r1;
        run_decrypt_test_vector::<Secp384r1>(
            "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497a\
             fb8156b91c3f5baa12b4d81b5f44f2eb40\
             2399e501ed395e834c44d5c85008ef0a8b281240c5d409e4d1b85a586e493332",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn test_vector_secp384r1_2() {
        use generic_ec::curves::Secp384r1;
        run_decrypt_test_vector::<Secp384r1>(
            "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa\
             5abb536caf174cc3258bf387f3e72e496c01\
             8163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e\
             018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e\
             018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e\
             018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
    }

    #[test]
    fn test_vector_secp384r1_3() {
        use generic_ec::curves::Secp384r1;
        run_decrypt_test_vector::<Secp384r1>(
            "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a\
             3e79b4895fe83593a0cbe39b4010d96c63\
             d39a10133ef7f68aabfc63253f45373375\
             39a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268\
             337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b\
             7f773eb58706",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
             6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
             206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    // ---- Expand function tests ----

    #[test]
    fn test_expand_exact_multiple() {
        let expanded = expand(&[1, 2, 3, 4], 8);
        assert_eq!(expanded, vec![1, 2, 3, 4, 1, 2, 3, 4]);
    }

    #[test]
    fn test_expand_with_remainder() {
        let expanded = expand(&[1, 2, 3, 4], 6);
        assert_eq!(expanded, vec![1, 2, 3, 4, 1, 2]);
    }

    #[test]
    fn test_expand_shorter_than_seed() {
        let expanded = expand(&[1, 2, 3, 4], 2);
        assert_eq!(expanded, vec![1, 2]);
    }

    #[test]
    fn test_expand_zero_length() {
        let expanded = expand(&[1, 2, 3, 4], 0);
        assert!(expanded.is_empty());
    }
}
