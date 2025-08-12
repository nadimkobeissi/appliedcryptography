//! # Collision-Resistant Hash Functions
//!
//! This module implements and demonstrates various hash functions and their properties
//! as covered in Topic 1.6 of the Applied Cryptography course.
//!
//! ## Key Properties
//!
//! 1. **Collision Resistance**: Hard to find two inputs with the same hash
//! 2. **Preimage Resistance**: Hard to find an input for a given hash
//! 3. **Second Preimage Resistance**: Hard to find a different input with the same hash
//!
//! ## Hash Functions Included
//!
//! - SHA-256, SHA-512 (SHA-2 family)
//! - SHA-3 (Keccak)
//! - BLAKE3 (modern, fast hash)
//! - MD5 (broken, for educational purposes)
//!
//! ## Applications
//!
//! - Password storage with salts
//! - Data integrity verification
//! - Proof-of-work systems

use crate::error::{CryptoError, Result};
use ::sha3::{Sha3_256, Sha3_512};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use blake3;
use md5::Digest as Md5Digest;
use pbkdf2::pbkdf2_hmac;
use scrypt::{Params as ScryptParams, scrypt};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Common trait for hash functions
pub trait HashFunction {
    /// Compute the hash of input data
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Get the output size in bytes
    fn output_size(&self) -> usize;

    /// Get the name of the hash function
    fn name(&self) -> &str;
}

/// SHA-256 hash function wrapper
pub struct SHA256;

impl HashFunction for SHA256 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        sha256::hash(data).to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }

    fn name(&self) -> &str {
        "SHA-256"
    }
}

/// SHA-256 hash function
pub mod sha256 {
    use super::*;

    /// Compute SHA-256 hash
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute SHA-256 hash and return as hex string
    pub fn hash_hex(data: &[u8]) -> String {
        hex::encode(hash(data))
    }
}

/// SHA-512 hash function
pub mod sha512 {
    use super::*;

    /// Compute SHA-512 hash
    pub fn hash(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute SHA-512 hash and return as hex string
    pub fn hash_hex(data: &[u8]) -> String {
        hex::encode(hash(data))
    }
}

/// SHA-3 hash functions
pub mod sha3 {
    use super::*;

    /// Compute SHA3-256 hash
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute SHA3-512 hash
    pub fn sha3_512(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// BLAKE3 hash function
pub mod blake {
    use super::*;

    /// Compute BLAKE3 hash (256-bit default)
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    /// Compute BLAKE3 hash with custom length
    pub fn hash_custom_length(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let mut output = vec![0u8; output_len];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    /// Compute keyed BLAKE3 hash (MAC)
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(key, data).as_bytes()
    }
}

/// MD5 hash function (BROKEN - educational only)
#[cfg(feature = "educational")]
pub mod md5_insecure {
    use super::*;

    /// Compute MD5 hash (INSECURE - educational only)
    pub fn hash(data: &[u8]) -> [u8; 16] {
        let mut hasher = md5::Md5::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Demonstrate MD5 is broken by showing known collisions
    pub fn demonstrate_collision() {
        println!("\n=== MD5 Collision Demo ===\n");

        // These are actual MD5 collisions found by researchers
        let msg1 = hex::decode(
            "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89\
             55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b\
             d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0\
             e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70",
        )
        .unwrap();

        let msg2 = hex::decode(
            "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89\
             55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b\
             d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0\
             e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70",
        )
        .unwrap();

        let hash1 = md5_insecure::hash(&msg1);
        let hash2 = md5_insecure::hash(&msg2);

        println!("Message 1 hash: {}", hex::encode(hash1));
        println!("Message 2 hash: {}", hex::encode(hash2));
        println!("\n⚠️  These different messages have the SAME MD5 hash!");
        println!("This proves MD5 is cryptographically broken!");

        assert_eq!(hash1, hash2);
    }
}

/// Password hashing utilities
pub mod password {
    use super::*;

    /// Hash a password with a random salt using PBKDF2
    pub fn hash_password_pbkdf2(password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let salt = generate_salt()?;
        let mut key = vec![0u8; 32];

        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);

        Ok((key, salt))
    }

    /// Verify a password against a PBKDF2 hash
    pub fn verify_password_pbkdf2(password: &str, hash: &[u8], salt: &[u8]) -> Result<bool> {
        let mut computed_hash = vec![0u8; hash.len()];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut computed_hash);

        Ok(constant_time_compare(hash, &computed_hash))
    }

    /// Hash a password using Argon2 (memory-hard function)
    pub fn hash_password_argon2(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            })
    }

    /// Verify a password against an Argon2 hash
    pub fn verify_password_argon2(password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| CryptoError::InvalidInput {
            reason: e.to_string(),
        })?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Hash a password using Scrypt (memory-hard function)
    pub fn hash_password_scrypt(password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let salt = generate_salt()?;
        let params = ScryptParams::new(15, 8, 1, 32).map_err(|e| CryptoError::InvalidInput {
            reason: e.to_string(),
        })?;

        let mut output = vec![0u8; 32];
        scrypt(password.as_bytes(), &salt, &params, &mut output).map_err(|e| {
            CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            }
        })?;

        Ok((output, salt))
    }

    /// Generate a random salt
    pub fn generate_salt() -> Result<Vec<u8>> {
        let mut salt = vec![0u8; 16];
        getrandom::fill(&mut salt)?;
        Ok(salt)
    }
}

/// Demonstrate the birthday paradox
pub fn birthday_paradox_demo(bits: usize) -> (usize, Duration) {
    println!("\n=== Birthday Paradox Demo ===");
    println!("Finding collisions in {}-bit hashes...", bits);

    let mask = (1u64 << bits) - 1;
    let mut seen = HashMap::new();
    let mut counter = 0u64;
    let start = Instant::now();

    loop {
        let data = counter.to_be_bytes();
        let hash = sha256::hash(&data);

        // Take only the first 'bits' bits
        let truncated = u64::from_be_bytes(hash[..8].try_into().unwrap()) & mask;

        if let Some(prev_counter) = seen.insert(truncated, counter) {
            let duration = start.elapsed();
            println!("Collision found after {} attempts", counter);
            println!("Expected: ~{} attempts", (1u64 << (bits / 2)) as f64 * 1.25);
            println!("Time taken: {:?}", duration);
            println!(
                "Values {} and {} have the same {}-bit hash",
                prev_counter, counter, bits
            );
            return (counter as usize, duration);
        }

        counter += 1;

        if counter > (1u64 << ((bits / 2) + 4)) {
            println!("No collision found in reasonable time");
            return (counter as usize, start.elapsed());
        }
    }
}

/// Proof of Work implementation (like Bitcoin mining)
pub struct ProofOfWork {
    difficulty: usize, // Number of leading zero bits required
}

impl ProofOfWork {
    /// Create a new PoW instance with given difficulty
    pub fn new(difficulty: usize) -> Self {
        Self { difficulty }
    }

    /// Find a nonce that produces a hash with required leading zeros
    pub fn mine(&self, data: &[u8]) -> (u64, [u8; 32], Duration) {
        let start = Instant::now();
        let mut nonce = 0u64;

        loop {
            let mut input = data.to_vec();
            input.extend_from_slice(&nonce.to_be_bytes());

            let hash = sha256::hash(&input);

            if self.check_difficulty(&hash) {
                let duration = start.elapsed();
                println!("Found valid nonce: {} after {:?}", nonce, duration);
                return (nonce, hash, duration);
            }

            nonce += 1;
        }
    }

    /// Check if a hash meets the difficulty requirement
    fn check_difficulty(&self, hash: &[u8]) -> bool {
        let mut leading_zeros = 0;

        for byte in hash {
            if *byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros() as usize;
                break;
            }
        }

        leading_zeros >= self.difficulty
    }

    /// Verify a proof of work
    pub fn verify(&self, data: &[u8], nonce: u64) -> bool {
        let mut input = data.to_vec();
        input.extend_from_slice(&nonce.to_be_bytes());

        let hash = sha256::hash(&input);
        self.check_difficulty(&hash)
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Rainbow table simulation for educational purposes
#[cfg(feature = "educational")]
pub struct RainbowTable {
    table: HashMap<Vec<u8>, String>,
}

#[cfg(feature = "educational")]
impl RainbowTable {
    /// Build a rainbow table for common passwords
    pub fn build(passwords: &[&str]) -> Self {
        let mut table = HashMap::new();

        for password in passwords {
            // Compute unsalted hash
            let hash = sha256::hash(password.as_bytes());
            table.insert(hash.to_vec(), password.to_string());
        }

        Self { table }
    }

    /// Attempt to crack a hash using the rainbow table
    pub fn crack(&self, hash: &[u8]) -> Option<String> {
        self.table.get(hash).cloned()
    }

    /// Demonstrate why salts defeat rainbow tables
    pub fn demonstrate_salt_protection() {
        println!("\n=== Rainbow Table vs Salt Demo ===\n");

        let passwords = vec!["password", "123456", "admin", "letmein"];
        let rainbow_table = RainbowTable::build(&passwords);

        // Unsalted hash (vulnerable)
        let password = "password";
        let unsalted_hash = sha256::hash(password.as_bytes());

        if let Some(cracked) = rainbow_table.crack(&unsalted_hash) {
            println!("❌ Unsalted hash cracked: {}", cracked);
        }

        // Salted hash (protected)
        let (salted_hash, salt) = password::hash_password_pbkdf2(password).unwrap();

        if rainbow_table.crack(&salted_hash).is_none() {
            println!("✅ Salted hash not in rainbow table!");
            println!("   Salt: {}", hex::encode(&salt));
        }

        println!("\n📝 Salts make precomputed rainbow tables useless!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = sha256::hash(data);
        assert_eq!(hash.len(), 32);

        // Test deterministic property
        let hash2 = sha256::hash(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let hash1 = sha256::hash(b"input1");
        let hash2 = sha256::hash(b"input2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blake3() {
        let data = b"BLAKE3 is fast!";
        let hash = blake::hash(data);
        assert_eq!(hash.len(), 32);

        // Test keyed hash
        let key = [0x42u8; 32];
        let keyed = blake::keyed_hash(&key, data);
        assert_ne!(hash, keyed);
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure_password123";

        // Test PBKDF2
        let (hash, salt) = password::hash_password_pbkdf2(password).unwrap();
        assert!(password::verify_password_pbkdf2(password, &hash, &salt).unwrap());
        assert!(!password::verify_password_pbkdf2("wrong_password", &hash, &salt).unwrap());

        // Test Argon2
        let argon2_hash = password::hash_password_argon2(password).unwrap();
        assert!(password::verify_password_argon2(password, &argon2_hash).unwrap());
        assert!(!password::verify_password_argon2("wrong_password", &argon2_hash).unwrap());
    }

    #[test]
    fn test_proof_of_work() {
        let pow = ProofOfWork::new(8); // 8 bits of difficulty (easy for testing)
        let data = b"Block data";

        let (nonce, hash, _duration) = pow.mine(data);
        assert!(pow.verify(data, nonce));

        // Verify the hash has required leading zeros
        assert_eq!(hash[0], 0);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];
        let c = vec![1, 2, 3, 4, 6];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }
}
