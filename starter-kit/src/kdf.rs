//! # Key Derivation Functions (KDFs)
//!
//! This module implements various key derivation functions used to derive
//! cryptographic keys from passwords or other key material.
//!
//! ## KDF Algorithms
//!
//! - **HKDF**: HMAC-based Extract-and-Expand Key Derivation Function
//! - **PBKDF2**: Password-Based Key Derivation Function 2
//! - **Argon2**: Memory-hard password hashing (winner of PHC)
//! - **Scrypt**: Memory-hard password hashing
//!
//! ## Use Cases
//!
//! - Deriving encryption keys from passwords
//! - Key stretching for password storage
//! - Deriving multiple keys from a single master key
//! - Creating unique per-message keys

use crate::error::{CryptoError, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
///
/// HKDF is used to derive strong cryptographic keys from potentially
/// weak input key material (IKM).
pub struct HkdfSha256 {
    prk: Vec<u8>, // Pseudorandom key
}

impl HkdfSha256 {
    /// Extract phase: Create a pseudorandom key from input key material
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (can be empty)
    /// * `ikm` - Input key material
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut prk = vec![0u8; 32]; // SHA256 output size
        hkdf.expand(&[], &mut prk).unwrap();
        let prk = prk.to_vec();
        Self { prk }
    }

    /// Expand phase: Derive output key material
    ///
    /// # Arguments
    /// * `info` - Context and application specific information
    /// * `length` - Desired length of output key material
    pub fn expand(&self, info: &[u8], length: usize) -> Result<Vec<u8>> {
        if length > 255 * 32 {
            return Err(CryptoError::InvalidInput {
                reason: "Output length too large for HKDF-SHA256".to_string(),
            });
        }

        let hkdf =
            Hkdf::<Sha256>::from_prk(&self.prk).map_err(|e| CryptoError::Generic(e.to_string()))?;
        let mut okm = vec![0u8; length];
        hkdf.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            })?;

        Ok(okm)
    }

    /// One-step HKDF: Extract and Expand
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        let hkdf = Self::extract(salt, ikm);
        hkdf.expand(info, length)
    }
}

impl Drop for HkdfSha256 {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

/// PBKDF2 (Password-Based Key Derivation Function 2)
///
/// PBKDF2 applies a pseudorandom function (HMAC) many times to increase
/// the computational cost of deriving the key.
pub struct Pbkdf2 {
    iterations: u32,
}

impl Pbkdf2 {
    /// Create a new PBKDF2 instance with specified iterations
    ///
    /// # Recommendations
    /// - Minimum: 100,000 iterations (NIST SP 800-63B)
    /// - For high security: 1,000,000+ iterations
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Derive a key using PBKDF2-HMAC-SHA256
    pub fn derive_sha256(&self, password: &[u8], salt: &[u8], output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        pbkdf2_hmac::<Sha256>(password, salt, self.iterations, &mut output);
        output
    }

    /// Derive a key using PBKDF2-HMAC-SHA512
    pub fn derive_sha512(&self, password: &[u8], salt: &[u8], output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        pbkdf2_hmac::<Sha512>(password, salt, self.iterations, &mut output);
        output
    }

    /// Generate a random salt
    pub fn generate_salt() -> Result<Vec<u8>> {
        let mut salt = vec![0u8; 16];
        getrandom::fill(&mut salt)?;
        Ok(salt)
    }
}

/// Argon2 - Memory-hard password hashing
///
/// Argon2 is the winner of the Password Hashing Competition and is
/// recommended for new applications.
pub struct Argon2Kdf {
    time_cost: u32,   // Number of iterations
    memory_cost: u32, // Memory usage in KB
    parallelism: u32, // Degree of parallelism
}

impl Argon2Kdf {
    /// Create with default parameters (Argon2id)
    pub fn default() -> Self {
        Self {
            time_cost: 3,
            memory_cost: 65536, // 64 MB
            parallelism: 4,
        }
    }

    /// Create with custom parameters
    pub fn new(time_cost: u32, memory_cost: u32, parallelism: u32) -> Self {
        Self {
            time_cost,
            memory_cost,
            parallelism,
        }
    }

    /// Derive a key from a password
    pub fn derive(&self, password: &[u8], salt: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let params = Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(output_len),
        )
        .map_err(|e| CryptoError::KeyDerivationFailed {
            reason: e.to_string(),
        })?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            })?;

        Ok(output)
    }

    /// Hash a password for storage (returns PHC string format)
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);

        let params = Params::new(self.memory_cost, self.time_cost, self.parallelism, None)
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            })?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            })
    }
}

/// Scrypt - Memory-hard password hashing
///
/// Scrypt is designed to be memory-hard, making it resistant to
/// hardware brute-force attacks.
pub struct ScryptKdf {
    log_n: u8, // CPU/memory cost parameter (2^log_n)
    r: u32,    // Block size
    p: u32,    // Parallelization parameter
}

impl ScryptKdf {
    /// Create with default parameters
    pub fn default() -> Self {
        Self {
            log_n: 15, // N = 32768
            r: 8,
            p: 1,
        }
    }

    /// Create with custom parameters
    pub fn new(log_n: u8, r: u32, p: u32) -> Self {
        Self { log_n, r, p }
    }

    /// Derive a key from a password
    pub fn derive(&self, password: &[u8], salt: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let params = ScryptParams::new(self.log_n, self.r, self.p, 32).map_err(|e| {
            CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            }
        })?;

        let mut output = vec![0u8; output_len];
        scrypt(password, salt, &params, &mut output).map_err(|e| {
            CryptoError::KeyDerivationFailed {
                reason: e.to_string(),
            }
        })?;

        Ok(output)
    }
}

/// Key stretching for weak passwords
pub fn stretch_password(
    password: &str,
    salt: &[u8],
    target_time_ms: u64,
) -> Result<(Vec<u8>, u32)> {
    use std::time::{Duration, Instant};

    // Start with a reasonable iteration count
    let mut iterations = 100_000u32;
    let best_iterations;
    let target_duration = Duration::from_millis(target_time_ms);

    // Calibrate iterations to reach target time
    loop {
        let start = Instant::now();
        let mut output = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut output);
        let elapsed = start.elapsed();

        if elapsed >= target_duration {
            best_iterations = iterations;
            break;
        }

        // Adjust iterations
        let ratio = target_duration.as_millis() as f64 / elapsed.as_millis() as f64;
        iterations = (iterations as f64 * ratio * 0.9) as u32; // 0.9 for safety margin

        if iterations > 10_000_000 {
            // Cap at 10 million iterations
            best_iterations = 10_000_000;
            break;
        }
    }

    let mut final_output = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        best_iterations,
        &mut final_output,
    );

    Ok((final_output, best_iterations))
}

/// Derive multiple keys from a master key using HKDF
pub struct MultiKeyDerivation {
    master_key: Vec<u8>,
}

impl MultiKeyDerivation {
    /// Create from a master key
    pub fn new(master_key: Vec<u8>) -> Self {
        Self { master_key }
    }

    /// Derive an encryption key
    pub fn derive_enc_key(&self, context: &[u8]) -> Result<[u8; 32]> {
        let mut info = b"ENCRYPTION_KEY".to_vec();
        info.extend_from_slice(context);

        let key = HkdfSha256::derive(b"", &self.master_key, &info, 32)?;
        Ok(key.try_into().unwrap())
    }

    /// Derive a MAC key
    pub fn derive_mac_key(&self, context: &[u8]) -> Result<[u8; 32]> {
        let mut info = b"MAC_KEY".to_vec();
        info.extend_from_slice(context);

        let key = HkdfSha256::derive(b"", &self.master_key, &info, 32)?;
        Ok(key.try_into().unwrap())
    }

    /// Derive a key with custom purpose
    pub fn derive_key(&self, purpose: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
        let mut info = purpose.to_vec();
        info.push(0x00); // Separator
        info.extend_from_slice(context);

        HkdfSha256::derive(b"", &self.master_key, &info, length)
    }
}

impl Drop for MultiKeyDerivation {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

/// Demonstrate different KDF use cases
#[cfg(feature = "educational")]
pub mod demonstrations {
    use super::*;

    /// Show why key stretching is important
    pub fn demonstrate_key_stretching() {
        println!("\n=== Key Stretching Demo ===\n");

        let weak_password = "password123";
        let salt = b"random_salt";

        println!("Weak password: {}", weak_password);

        // Fast hash (vulnerable to brute force)
        let start = std::time::Instant::now();
        let mut fast_key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(weak_password.as_bytes(), salt, 1, &mut fast_key);
        println!("1 iteration: {:?}", start.elapsed());

        // Slow hash (resistant to brute force)
        let start = std::time::Instant::now();
        let mut slow_key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(weak_password.as_bytes(), salt, 100_000, &mut slow_key);
        println!("100,000 iterations: {:?}", start.elapsed());

        println!("\n📝 Key stretching makes brute force attacks much slower!");
    }

    /// Compare memory-hard vs compute-hard KDFs
    pub fn compare_kdf_types() {
        println!("\n=== KDF Types Comparison ===\n");

        println!("Compute-hard (PBKDF2):");
        println!("  - Slows down by repeated computation");
        println!("  - Vulnerable to GPU/ASIC acceleration");
        println!("  - Good for compatibility");

        println!("\nMemory-hard (Argon2/Scrypt):");
        println!("  - Requires significant memory");
        println!("  - Resistant to parallel hardware attacks");
        println!("  - Better security but higher resource usage");

        println!("\n📝 Choose based on your threat model and constraints!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let okm1 = HkdfSha256::derive(salt, ikm, info, 32).unwrap();
        let okm2 = HkdfSha256::derive(salt, ikm, info, 32).unwrap();

        // Deterministic
        assert_eq!(okm1, okm2);
        assert_eq!(okm1.len(), 32);
    }

    #[test]
    fn test_pbkdf2() {
        let pbkdf2 = Pbkdf2::new(1000);
        let password = b"password";
        let salt = b"salt1234";

        let key1 = pbkdf2.derive_sha256(password, salt, 32);
        let key2 = pbkdf2.derive_sha256(password, salt, 32);

        // Deterministic
        assert_eq!(key1, key2);

        // Different salt produces different key
        let key3 = pbkdf2.derive_sha256(password, b"different_salt", 32);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_argon2() {
        let argon2 = Argon2Kdf::default();
        let password = b"secure_password";
        let salt = b"random_salt_16b!"; // 16 bytes

        let key = argon2.derive(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Different password produces different key
        let key2 = argon2.derive(b"different_password", salt, 32).unwrap();
        assert_ne!(key, key2);
    }

    #[test]
    fn test_scrypt() {
        let scrypt = ScryptKdf::default();
        let password = b"password";
        let salt = b"NaCl";

        let key = scrypt.derive(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_multi_key_derivation() {
        let master = vec![0x42u8; 32];
        let mkd = MultiKeyDerivation::new(master);

        let enc_key = mkd.derive_enc_key(b"context1").unwrap();
        let mac_key = mkd.derive_mac_key(b"context1").unwrap();

        // Different purposes produce different keys
        assert_ne!(enc_key, mac_key);

        // Same purpose and context produces same key
        let enc_key2 = mkd.derive_enc_key(b"context1").unwrap();
        assert_eq!(enc_key, enc_key2);
    }

    #[test]
    fn test_hkdf_expand_limits() {
        let hkdf = HkdfSha256::extract(b"salt", b"ikm");

        // Maximum valid length
        let result = hkdf.expand(b"info", 255 * 32);
        assert!(result.is_ok());

        // Too large
        let result = hkdf.expand(b"info", 255 * 32 + 1);
        assert!(result.is_err());
    }
}
