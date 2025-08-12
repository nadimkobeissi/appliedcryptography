//! # Basic Cryptography Examples
//!
//! This example demonstrates the usage of various cryptographic primitives
//! from the Applied Cryptography Starter Kit.
//!
//! Run with: `cargo run --example basic_crypto`
//! Run with educational features: `cargo run --example basic_crypto --features educational`

use applied_crypto_starter_kit::{
    error::Result,
    hashing::{ProofOfWork, blake, password, sha3, sha256},
    kdf::{Argon2Kdf, HkdfSha256, Pbkdf2},
    key_exchange::{ClassicDiffieHellman, X25519DiffieHellman},
    mac::{HmacSha256, hmac_sha256},
    one_time_pad::{OneTimePad, generate_random_key},
    pseudorandom::{PseudorandomFunction, PseudorandomGenerator, PseudorandomPermutation},
    signatures::{EcdsaP256, Ed25519},
    symmetric::{AuthenticatedEncryption, aes_ctr, cbc},
    utils::to_hex,
};

fn main() -> Result<()> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("    Applied Cryptography Starter Kit - Basic Examples");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Run all demonstrations
    demonstrate_one_time_pad()?;
    demonstrate_pseudorandom()?;
    demonstrate_symmetric_encryption()?;
    demonstrate_hashing()?;
    demonstrate_key_exchange()?;
    demonstrate_digital_signatures()?;
    demonstrate_mac()?;
    demonstrate_kdf()?;

    #[cfg(feature = "educational")]
    {
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("    Educational: Security Vulnerabilities");
        println!("═══════════════════════════════════════════════════════════════\n");
        demonstrate_vulnerabilities()?;
    }

    println!("\n✅ All examples completed successfully!");
    Ok(())
}

fn demonstrate_one_time_pad() -> Result<()> {
    println!("📝 One-Time Pad (Perfect Secrecy)");
    println!("─────────────────────────────────────");

    let message = b"ATTACK AT DAWN!";
    let key = generate_random_key(message.len())?;

    println!("Message:    {}", String::from_utf8_lossy(message));
    println!("Key (hex):  {}", to_hex(&key));

    let otp = OneTimePad::new(key.clone());
    let ciphertext = otp.encrypt(message)?;
    println!("Ciphertext: {}", to_hex(&ciphertext));

    let decrypted = otp.decrypt(&ciphertext)?;
    println!("Decrypted:  {}", String::from_utf8_lossy(&decrypted));

    assert_eq!(message.to_vec(), decrypted);
    println!("✓ Encryption and decryption successful\n");

    Ok(())
}

fn demonstrate_pseudorandom() -> Result<()> {
    println!("🎲 Pseudorandom Generators and Functions");
    println!("─────────────────────────────────────────");

    // PRG
    let seed = [0x42u8; 32];
    let mut prg = PseudorandomGenerator::from_seed(seed);
    let random_bytes = prg.generate(16);
    println!("PRG output (16 bytes): {}", to_hex(&random_bytes));

    // PRF
    let prf = PseudorandomFunction::new(vec![0x42; 32]);
    let prf_output = prf.evaluate(b"input data");
    println!("PRF output: {}", to_hex(&prf_output));

    // PRP (Block Cipher)
    let prp = PseudorandomPermutation::new([0x42u8; 32]);
    let block = [0u8; 16];
    let permuted = prp.permute(block);
    println!("PRP output: {}", to_hex(&permuted));

    println!("✓ Pseudorandom primitives demonstrated\n");
    Ok(())
}

fn demonstrate_symmetric_encryption() -> Result<()> {
    println!("🔐 Symmetric Encryption Modes");
    println!("──────────────────────────────");

    let key = [0x42u8; 32];
    let plaintext = b"This is a secret message that needs encryption!";

    // CTR Mode (recommended)
    println!("CTR Mode:");
    let ctr_ciphertext = aes_ctr::encrypt(&key, plaintext)?;
    let ctr_decrypted = aes_ctr::decrypt(&key, &ctr_ciphertext)?;
    println!("  Ciphertext length: {} bytes", ctr_ciphertext.len());
    println!(
        "  ✓ Decryption successful: {}",
        String::from_utf8_lossy(&ctr_decrypted[..20])
    );

    // CBC Mode
    println!("\nCBC Mode:");
    let cbc_ciphertext = cbc::encrypt(&key, plaintext)?;
    cbc::decrypt(&key, &cbc_ciphertext)?;
    println!(
        "  Ciphertext length: {} bytes (includes padding)",
        cbc_ciphertext.len()
    );
    println!("  ✓ Decryption successful");

    // Authenticated Encryption (Encrypt-then-MAC)
    println!("\nAuthenticated Encryption:");
    let enc_key = [0x01u8; 32];
    let mac_key = [0x02u8; 32];
    let ae = AuthenticatedEncryption::new(enc_key, mac_key);

    let ae_ciphertext = ae.encrypt(plaintext)?;
    ae.decrypt(&ae_ciphertext)?;
    println!("  Ciphertext + MAC: {} bytes", ae_ciphertext.len());
    println!("  ✓ Authentication and decryption successful");

    println!();
    Ok(())
}

fn demonstrate_hashing() -> Result<()> {
    println!("🔍 Hash Functions and Applications");
    println!("────────────────────────────────────");

    let data = b"Hello, Cryptographic Hash Functions!";

    // Various hash functions
    println!("Hash outputs for: {:?}", String::from_utf8_lossy(data));
    println!("  SHA-256:  {}", sha256::hash_hex(data));
    println!("  SHA3-256: {}", to_hex(&sha3::sha3_256(data)));
    println!("  BLAKE3:   {}", to_hex(&blake::hash(data)));

    // Password hashing
    println!("\nPassword Hashing:");
    let password = "mysecretpassword";
    let (hash, salt) = password::hash_password_pbkdf2(password)?;
    println!("  PBKDF2 hash: {}", to_hex(&hash[..16]));
    println!("  Salt: {}", to_hex(&salt));

    let valid = password::verify_password_pbkdf2(password, &hash, &salt)?;
    println!("  ✓ Password verification: {}", valid);

    // Proof of Work
    println!("\nProof of Work (8 bits difficulty):");
    let pow = ProofOfWork::new(8);
    let (nonce, hash, duration) = pow.mine(b"Block #42");
    println!("  Found nonce: {} in {:?}", nonce, duration);
    println!("  Hash: {}", to_hex(&hash[..8]));

    println!();
    Ok(())
}

fn demonstrate_key_exchange() -> Result<()> {
    println!("🤝 Diffie-Hellman Key Exchange");
    println!("─────────────────────────────");

    // X25519 (Modern, recommended)
    println!("X25519 ECDH:");
    let alice = X25519DiffieHellman::new();
    let bob = X25519DiffieHellman::new();

    let alice_public = alice.public_key_bytes();
    let bob_public = bob.public_key_bytes();

    println!("  Alice's public: {}", to_hex(&alice_public[..16]));
    println!("  Bob's public:   {}", to_hex(&bob_public[..16]));

    let alice_shared = alice.compute_shared_secret(&bob_public)?;
    let bob_shared = bob.compute_shared_secret(&alice_public)?;

    println!("  Shared secret:  {}", to_hex(&alice_shared[..16]));
    assert_eq!(alice_shared, bob_shared);
    println!("  ✓ Shared secrets match!");

    // Classic DH (Educational)
    println!("\nClassic DH (RFC 3526 Group):");
    let dh = ClassicDiffieHellman::new_rfc3526_2048();
    let alice_private = dh.generate_private_key();
    let alice_public = dh.compute_public_key(&alice_private);
    let bob_private = dh.generate_private_key();
    let bob_public = dh.compute_public_key(&bob_private);

    let alice_shared = dh.compute_shared_secret(&alice_private, &bob_public)?;
    let bob_shared = dh.compute_shared_secret(&bob_private, &alice_public)?;

    assert_eq!(alice_shared, bob_shared);
    println!("  ✓ Classic DH key exchange successful");

    println!();
    Ok(())
}

fn demonstrate_digital_signatures() -> Result<()> {
    println!("✍️  Digital Signatures");
    println!("───────────────────");

    let message = b"Sign this important document";

    // Ed25519 (Recommended)
    println!("Ed25519:");
    let ed_signer = Ed25519::generate();
    let ed_signature = ed_signer.sign(message);
    let ed_public = ed_signer.public_key_bytes();

    println!("  Public key: {}", to_hex(&ed_public[..16]));
    println!("  Signature:  {}", to_hex(&ed_signature[..16]));

    ed_signer.verify(message, &ed_signature)?;
    Ed25519::verify_with_public_key(&ed_public, message, &ed_signature)?;
    println!("  ✓ Signature verified!");

    // ECDSA P-256
    println!("\nECDSA P-256:");
    let ecdsa_signer = EcdsaP256::generate();
    let ecdsa_signature = ecdsa_signer.sign(message);

    println!("  Signature length: {} bytes", ecdsa_signature.len());
    ecdsa_signer.verify(message, &ecdsa_signature)?;
    println!("  ✓ ECDSA signature verified!");

    println!();
    Ok(())
}

fn demonstrate_mac() -> Result<()> {
    println!("🔏 Message Authentication Codes");
    println!("──────────────────────────────");

    let message = b"Authenticate this message";
    let key = b"secret_mac_key";

    // HMAC-SHA256
    println!("HMAC-SHA256:");
    let hmac = HmacSha256::new(key.to_vec());
    let tag = hmac.compute(message);
    println!("  MAC tag: {}", to_hex(&tag[..16]));

    hmac.verify(message, &tag)?;
    println!("  ✓ MAC verified successfully");

    // Quick HMAC function
    let quick_tag = hmac_sha256(key, message);
    assert_eq!(tag, quick_tag);
    println!("  ✓ Quick function produces same result");

    println!();
    Ok(())
}

fn demonstrate_kdf() -> Result<()> {
    println!("🔑 Key Derivation Functions");
    println!("─────────────────────────");

    // HKDF
    println!("HKDF:");
    let master_key = b"master_secret_key";
    let salt = b"optional_salt";
    let info = b"application_context";

    let derived1 = HkdfSha256::derive(salt, master_key, info, 32)?;
    let derived2 = HkdfSha256::derive(salt, master_key, b"different_context", 32)?;

    println!("  Key 1: {}", to_hex(&derived1[..16]));
    println!("  Key 2: {}", to_hex(&derived2[..16]));
    println!("  ✓ Different contexts produce different keys");

    // PBKDF2
    println!("\nPBKDF2 (100,000 iterations):");
    let pbkdf2 = Pbkdf2::new(100_000);
    let password = b"user_password";
    let salt = Pbkdf2::generate_salt()?;

    let start = std::time::Instant::now();
    let key = pbkdf2.derive_sha256(password, &salt, 32);
    let duration = start.elapsed();

    println!("  Derived key: {}", to_hex(&key[..16]));
    println!("  Time taken: {:?}", duration);

    // Argon2
    println!("\nArgon2id (memory-hard):");
    let argon2 = Argon2Kdf::default();
    let argon2_key = argon2.derive(password, &salt, 32)?;
    println!("  Derived key: {}", to_hex(&argon2_key[..16]));
    println!("  ✓ Memory-hard KDF completed");

    println!();
    Ok(())
}

#[cfg(feature = "educational")]
fn demonstrate_vulnerabilities() -> Result<()> {
    use applied_crypto_starter_kit::hashing::RainbowTable;
    use applied_crypto_starter_kit::hashing::md5_insecure;
    use applied_crypto_starter_kit::key_exchange::discrete_log;
    use applied_crypto_starter_kit::mac::timing_attacks;
    use applied_crypto_starter_kit::one_time_pad;
    use applied_crypto_starter_kit::symmetric;
    use symmetric::ecb;

    // OTP key reuse
    println!("⚠️  One-Time Pad Key Reuse:");
    one_time_pad::demonstrate_key_reuse_vulnerability()?;

    // ECB mode patterns
    println!("\n⚠️  ECB Mode Pattern Leakage:");
    ecb::demonstrate_ecb_vulnerability();

    // CTR malleability
    println!("\n⚠️  CTR Mode Malleability:");
    symmetric::demonstrate_ctr_malleability();

    // Timing attacks
    println!("\n⚠️  Timing Attack on MAC Verification:");
    timing_attacks::demonstrate_timing_attack();

    // MD5 collisions
    println!("\n⚠️  MD5 Hash Collision:");
    md5_insecure::demonstrate_collision();

    // Rainbow table
    println!("\n⚠️  Rainbow Table Salt Protection:");
    RainbowTable::demonstrate_salt_protection();

    // Finite-field Diffie-Hellman
    println!("\n⚠️  Rainbow Table Salt Protection:");
    discrete_log::demonstrate_hardness();

    Ok(())
}
