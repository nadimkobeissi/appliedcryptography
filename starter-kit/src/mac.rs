//! # Message Authentication Codes (MACs)
//!
//! This module implements various MAC algorithms for ensuring message integrity
//! and authenticity, as covered throughout the Applied Cryptography course.
//!
//! ## MAC Algorithms
//!
//! - **HMAC**: Hash-based Message Authentication Code
//! - **Poly1305**: Fast one-time authenticator
//!
//! ## Security Properties
//!
//! - **Unforgeable**: Can't create valid MAC without the key
//! - **Deterministic**: Same key and message always produce same MAC
//! - **Collision-resistant**: Different messages produce different MACs

use crate::error::{CryptoError, Result};
use cipher::KeyInit;
use hmac::{Hmac, Mac as HmacTrait};
use poly1305::{Key as Poly1305Key, Poly1305 as Poly1305Mac, universal_hash::UniversalHash};
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// HMAC implementation with various hash functions
pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Compute MAC for a message
    pub fn compute(&self, message: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(&self.key)
            .expect("HMAC can accept any key size");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    /// Verify a MAC (constant-time comparison)
    pub fn verify(&self, message: &[u8], tag: &[u8; 32]) -> Result<()> {
        let computed = self.compute(message);

        if computed.ct_eq(tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// HMAC with SHA-512
pub struct HmacSha512 {
    key: Vec<u8>,
}

impl HmacSha512 {
    /// Create a new HMAC-SHA512 instance
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Compute MAC for a message
    pub fn compute(&self, message: &[u8]) -> [u8; 64] {
        let mut mac = <Hmac<Sha512> as HmacTrait>::new_from_slice(&self.key)
            .expect("HMAC can accept any key size");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    /// Verify a MAC
    pub fn verify(&self, message: &[u8], tag: &[u8; 64]) -> Result<()> {
        let computed = self.compute(message);

        if computed.ct_eq(tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }
}

/// Generic HMAC wrapper for any hash function
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as HmacTrait>::new_from_slice(key).expect("HMAC can accept any key size");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Generic HMAC wrapper for any hash function
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mac =
        <Hmac<Sha512> as HmacTrait>::new_from_slice(key).expect("HMAC can accept any key size");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Generic HMAC wrapper for any hash function
pub fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha3_256> as HmacTrait>::new_from_slice(key).expect("HMAC can accept any key size");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Poly1305 one-time authenticator
///
/// Poly1305 is extremely fast but requires a unique key for each message.
/// It's typically used with a stream cipher (like ChaCha20) to generate
/// per-message keys.
pub struct Poly1305 {
    key: [u8; 32],
}

impl Poly1305 {
    /// Create a new Poly1305 instance
    ///
    /// # Security Warning
    /// The key MUST be unique for each message. Never reuse a Poly1305 key!
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Compute Poly1305 MAC
    pub fn compute(&self, message: &[u8]) -> [u8; 16] {
        let key = Poly1305Key::from(self.key);
        let mut poly = Poly1305Mac::new(&key);
        poly.update_padded(message);
        poly.finalize().into()
    }

    /// Verify a Poly1305 MAC
    pub fn verify(&self, message: &[u8], tag: &[u8; 16]) -> Result<()> {
        let computed = self.compute(message);

        if computed.ct_eq(tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Incremental MAC computation for streaming data
pub struct IncrementalMac {
    mac: Hmac<Sha256>,
}

impl IncrementalMac {
    /// Create a new incremental MAC
    pub fn new(key: &[u8]) -> Result<Self> {
        let mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(key)
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        Ok(Self { mac })
    }

    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// Finalize and get the MAC
    pub fn finalize(self) -> [u8; 32] {
        self.mac.finalize().into_bytes().into()
    }

    /// Clone the current state (useful for branching computations)
    pub fn clone_state(&self) -> Self {
        Self {
            mac: self.mac.clone(),
        }
    }
}

/// Demonstrate why H(key || message) is insecure
#[cfg(feature = "educational")]
pub mod insecure_constructions {
    use crate::hashing::sha256;

    /// Insecure MAC construction: H(key || message)
    ///
    /// This is vulnerable to length extension attacks!
    pub fn insecure_mac_prepend(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(key);
        data.extend_from_slice(message);
        sha256::hash(&data)
    }

    /// Insecure MAC construction: H(message || key)
    ///
    /// This is vulnerable to collision attacks!
    pub fn insecure_mac_append(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(message);
        data.extend_from_slice(key);
        sha256::hash(&data)
    }

    /// Demonstrate collision vulnerability
    pub fn demonstrate_collision_vulnerability() {
        println!("\n=== Collision Attack on H(message || key) ===\n");

        println!("If attacker finds two messages with same hash:");
        println!("  H(m1) = H(m2)");
        println!("Then: H(m1 || key) = H(m2 || key)");
        println!("\n⚠️  Same MAC for different messages!");

        println!("\n✅ Solution: Use HMAC!");
    }
}

/// Timing attack demonstration and defense
#[cfg(feature = "educational")]
pub mod timing_attacks {
    use std::time::{Duration, Instant};

    /// Vulnerable MAC verification (with timing leak)
    pub fn vulnerable_verify(computed: &[u8], received: &[u8]) -> bool {
        if computed.len() != received.len() {
            return false;
        }

        // BAD: Returns early on first mismatch
        for i in 0..computed.len() {
            if computed[i] != received[i] {
                return false; // Timing leak!
            }
        }

        true
    }

    /// Secure MAC verification (constant-time)
    pub fn secure_verify(computed: &[u8], received: &[u8]) -> bool {
        if computed.len() != received.len() {
            return false;
        }

        // GOOD: Always compares all bytes
        let mut result = 0u8;
        for i in 0..computed.len() {
            result |= computed[i] ^ received[i];
        }

        result == 0
    }

    /// Demonstrate timing attack
    pub fn demonstrate_timing_attack() {
        println!("\n=== MAC Timing Attack Demo ===\n");

        let correct_mac = [0x42u8; 16];
        let mut attacker_guess = [0x00u8; 16];

        println!("Correct MAC: {}", hex::encode(correct_mac));

        // Simulate timing measurements
        for position in 0..16 {
            let mut best_byte = 0u8;
            let mut best_time = Duration::ZERO;

            for byte_guess in 0..=255 {
                attacker_guess[position] = byte_guess;

                let start = Instant::now();
                for _ in 0..1000 {
                    vulnerable_verify(&correct_mac, &attacker_guess);
                }
                let elapsed = start.elapsed();

                if elapsed > best_time {
                    best_time = elapsed;
                    best_byte = byte_guess;
                }
            }

            attacker_guess[position] = best_byte;

            if position < 3 {
                println!("Position {}: found byte 0x{:02x}", position, best_byte);
            }
        }

        println!("\n⚠️  Timing leaks can reveal MAC bytes one at a time!");
        println!("✅  Always use constant-time comparison!");
    }
}

/// Key derivation for MAC keys
pub fn derive_mac_key(master_key: &[u8], context: &[u8]) -> [u8; 32] {
    // Use HMAC as a PRF for key derivation
    let mut mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(master_key)
        .expect("HMAC can accept any key size");
    mac.update(b"MAC_KEY");
    mac.update(context);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = b"test_key";
        let message = b"Hello, HMAC!";

        let mac1 = hmac_sha256(key, message);
        let mac2 = hmac_sha256(key, message);

        // Deterministic
        assert_eq!(mac1, mac2);

        // Different message produces different MAC
        let mac3 = hmac_sha256(key, b"Different message");
        assert_ne!(mac1, mac3);
    }

    #[test]
    fn test_hmac_verification() {
        let hmac = HmacSha256::new(b"secret_key".to_vec());
        let message = b"Authenticated message";

        let tag = hmac.compute(message);

        // Correct tag verifies
        assert!(hmac.verify(message, &tag).is_ok());

        // Wrong tag fails
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0x01;
        assert!(hmac.verify(message, &wrong_tag).is_err());

        // Wrong message fails
        assert!(hmac.verify(b"Wrong message", &tag).is_err());
    }

    #[test]
    fn test_poly1305() {
        let key = [0x42u8; 32];
        let poly = Poly1305::new(key);
        let message = b"One-time authenticated message";

        let tag = poly.compute(message);
        assert_eq!(tag.len(), 16);

        // Verification should succeed
        assert!(poly.verify(message, &tag).is_ok());

        // Wrong message should fail
        assert!(poly.verify(b"Wrong", &tag).is_err());
    }

    #[test]
    fn test_incremental_mac() {
        let key = b"incremental_key";
        let mut mac = IncrementalMac::new(key).unwrap();

        mac.update(b"Hello, ");
        mac.update(b"incremental ");
        mac.update(b"MAC!");

        let result1 = mac.finalize();

        // Compare with all-at-once computation
        let result2 = hmac_sha256(key, b"Hello, incremental MAC!");

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_different_keys_different_macs() {
        let message = b"Same message";

        let mac1 = hmac_sha256(b"key1", message);
        let mac2 = hmac_sha256(b"key2", message);

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_key_derivation() {
        let master = b"master_secret";
        let context1 = b"context1";
        let context2 = b"context2";

        let key1 = derive_mac_key(master, context1);
        let key2 = derive_mac_key(master, context2);

        // Different contexts produce different keys
        assert_ne!(key1, key2);

        // Same context produces same key
        let key3 = derive_mac_key(master, context1);
        assert_eq!(key1, key3);
    }

    #[test]
    #[cfg(feature = "educational")]
    fn test_timing_safe_comparison() {
        use timing_attacks::{secure_verify, vulnerable_verify};

        let mac1 = [0x42u8; 16];
        let mac2 = [0x42u8; 16];
        let mac3 = [0x43u8; 16];

        // Both should give same results
        assert!(vulnerable_verify(&mac1, &mac2));
        assert!(secure_verify(&mac1, &mac2));

        assert!(!vulnerable_verify(&mac1, &mac3));
        assert!(!secure_verify(&mac1, &mac3));
    }
}
