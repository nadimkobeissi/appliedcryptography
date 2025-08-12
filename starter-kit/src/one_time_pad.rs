//! # One-Time Pad (OTP) Implementation
//!
//! This module demonstrates the One-Time Pad cipher, which provides perfect secrecy
//! when used correctly. This implementation is for educational purposes to understand
//! the concepts from Topic 1.2 of the Applied Cryptography course.
//!
//! ## Perfect Secrecy
//!
//! The OTP is the only encryption scheme proven to provide perfect secrecy, meaning
//! that the ciphertext reveals absolutely no information about the plaintext without
//! the key.
//!
//! ## Requirements for Perfect Secrecy
//!
//! 1. The key must be truly random
//! 2. The key must be at least as long as the message
//! 3. The key must never be reused
//! 4. The key must be kept completely secret
//!
//! ## Limitations
//!
//! - Key distribution problem: How do you securely share a key as long as the message?
//! - Key storage: Storing keys as long as all messages is impractical
//! - No integrity protection: OTP provides confidentiality but not authentication
//!
//! ## Example
//!
//! ```rust
//! use applied_crypto_starter_kit::one_time_pad::{OneTimePad, generate_random_key};
//!
//! let message = b"Hello, World!";
//! let key = generate_random_key(message.len()).unwrap();
//!
//! let otp = OneTimePad::new(key.clone());
//! let ciphertext = otp.encrypt(message).unwrap();
//! let plaintext = otp.decrypt(&ciphertext).unwrap();
//!
//! assert_eq!(plaintext, message);
//! ```

use crate::error::{CryptoError, Result};
use zeroize::Zeroize;

/// One-Time Pad cipher implementation
#[derive(Clone)]
pub struct OneTimePad {
    /// The secret key (must be as long as the message)
    key: Vec<u8>,
}

impl OneTimePad {
    /// Create a new One-Time Pad with the given key
    ///
    /// # Arguments
    /// * `key` - The secret key (must be as long as the message to encrypt)
    ///
    /// # Example
    /// ```rust
    /// use applied_crypto_starter_kit::one_time_pad::OneTimePad;
    ///
    /// let key = vec![0x42; 16]; // In practice, use a random key!
    /// let otp = OneTimePad::new(key);
    /// ```
    pub fn new(key: Vec<u8>) -> Self {
        OneTimePad { key }
    }

    /// Encrypt a message using the one-time pad
    ///
    /// # Arguments
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The encrypted ciphertext
    /// * `Err(CryptoError)` - If the key is shorter than the plaintext
    ///
    /// # Security Warning
    /// The key must NEVER be reused! Each key should only encrypt one message.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.key.len() < plaintext.len() {
            return Err(CryptoError::InvalidKeySize {
                expected: plaintext.len(),
                actual: self.key.len(),
            });
        }

        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(self.key.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        Ok(ciphertext)
    }

    /// Decrypt a ciphertext using the one-time pad
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The decrypted plaintext
    /// * `Err(CryptoError)` - If the key is shorter than the ciphertext
    ///
    /// # Note
    /// Decryption is identical to encryption in OTP (XOR is its own inverse)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // In OTP, encryption and decryption are the same operation
        self.encrypt(ciphertext)
    }

    /// Get the key length
    pub fn key_len(&self) -> usize {
        self.key.len()
    }
}

impl Drop for OneTimePad {
    fn drop(&mut self) {
        // Securely zero the key from memory when dropped
        self.key.zeroize();
    }
}

/// Generate a cryptographically secure random key
///
/// # Arguments
/// * `length` - The desired key length in bytes
///
/// # Returns
/// * `Ok(Vec<u8>)` - A random key of the specified length
/// * `Err(CryptoError)` - If random generation fails
pub fn generate_random_key(length: usize) -> Result<Vec<u8>> {
    let mut key = vec![0u8; length];
    getrandom::fill(&mut key).map_err(|e| CryptoError::RandomGenerationFailed {
        reason: e.to_string(),
    })?;
    Ok(key)
}

/// Demonstrates why key reuse breaks OTP security
///
/// # Educational Purpose Only
/// This function shows how XORing two ciphertexts encrypted with the same key
/// reveals information about the plaintexts.
#[cfg(feature = "educational")]
pub fn demonstrate_key_reuse_vulnerability() -> Result<()> {
    println!("\n=== OTP Key Reuse Vulnerability Demo ===\n");

    // Generate a key
    let key = generate_random_key(50)?;
    let otp = OneTimePad::new(key);

    // Two different messages
    let msg1 = b"ATTACK AT DAWN. THE ENEMY IS APPROACHING FROM EAST";
    let msg2 = b"RETREAT NOW. ABANDON THE POSITION AND FALL BACK!!!";

    // Encrypt both with the same key (NEVER DO THIS!)
    let cipher1 = otp.encrypt(msg1)?;
    let cipher2 = otp.encrypt(msg2)?;

    // XOR the two ciphertexts
    let xor_ciphers: Vec<u8> = cipher1
        .iter()
        .zip(cipher2.iter())
        .map(|(c1, c2)| c1 ^ c2)
        .collect();

    // This equals msg1 XOR msg2 (the key cancels out!)
    let msg_xor: Vec<u8> = msg1
        .iter()
        .zip(msg2.iter())
        .map(|(m1, m2)| m1 ^ m2)
        .collect();

    println!("When the same OTP key is reused:");
    println!("C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2");
    println!("\nThis reveals the XOR of the two plaintexts!");
    println!("XOR of ciphertexts: {:?}", hex::encode(&xor_ciphers[..20]));
    println!("XOR of plaintexts:  {:?}", hex::encode(&msg_xor[..20]));
    assert_eq!(xor_ciphers, msg_xor);

    println!("\n⚠️  Key reuse completely breaks OTP security!");

    Ok(())
}

/// Demonstrates the Vernam cipher (binary OTP)
///
/// The Vernam cipher is the original patent for OTP using binary data
pub struct VernamCipher {
    tape: Vec<bool>,
    position: usize,
}

impl VernamCipher {
    /// Create a new Vernam cipher with a random tape
    pub fn new(length: usize) -> Result<Self> {
        let mut tape = vec![false; length];

        for bit in tape.iter_mut() {
            *bit = rand::random::<bool>();
        }

        Ok(VernamCipher { tape, position: 0 })
    }

    /// Encrypt/decrypt a single bit
    pub fn process_bit(&mut self, bit: bool) -> Result<bool> {
        if self.position >= self.tape.len() {
            return Err(CryptoError::InvalidInput {
                reason: "Tape exhausted - cannot reuse OTP key".to_string(),
            });
        }

        let result = bit ^ self.tape[self.position];
        self.position += 1;
        Ok(result)
    }

    /// Process a byte as 8 bits
    pub fn process_byte(&mut self, byte: u8) -> Result<u8> {
        let mut result = 0u8;
        for i in 0..8 {
            let bit = (byte >> (7 - i)) & 1 == 1;
            let encrypted_bit = self.process_bit(bit)?;
            if encrypted_bit {
                result |= 1 << (7 - i);
            }
        }
        Ok(result)
    }
}

/// Calculate the Shannon entropy of a byte sequence
///
/// This demonstrates that OTP ciphertext has maximum entropy
pub fn calculate_entropy(data: &[u8]) -> f64 {
    let mut frequency = [0u32; 256];

    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in frequency.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_correctness() {
        let plaintext = b"Hello, World!";
        let key = generate_random_key(plaintext.len()).unwrap();

        let otp = OneTimePad::new(key);
        let ciphertext = otp.encrypt(plaintext).unwrap();
        let decrypted = otp.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_otp_different_keys_different_ciphertexts() {
        let plaintext = b"Secret Message";

        let key1 = generate_random_key(plaintext.len()).unwrap();
        let key2 = generate_random_key(plaintext.len()).unwrap();

        let otp1 = OneTimePad::new(key1);
        let otp2 = OneTimePad::new(key2);

        let cipher1 = otp1.encrypt(plaintext).unwrap();
        let cipher2 = otp2.encrypt(plaintext).unwrap();

        // With overwhelming probability, different keys produce different ciphertexts
        assert_ne!(cipher1, cipher2);
    }

    #[test]
    fn test_key_too_short() {
        let plaintext = b"This is a long message";
        let key = vec![0x42; 5]; // Key too short

        let otp = OneTimePad::new(key);
        let result = otp.encrypt(plaintext);

        assert!(matches!(result, Err(CryptoError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_vernam_cipher() {
        let mut cipher = VernamCipher::new(100).unwrap();
        let byte = 0b10101010;

        let encrypted = cipher.process_byte(byte).unwrap();

        // Reset cipher for decryption (in practice, receiver would have same tape)
        cipher.position = 0;
        let decrypted = cipher.process_byte(encrypted).unwrap();

        assert_eq!(byte, decrypted);
    }

    #[test]
    fn test_entropy_calculation() {
        // Uniform random data should have high entropy (close to 8 bits per byte)
        let random_data = generate_random_key(1000).unwrap();
        let entropy = calculate_entropy(&random_data);
        assert!(entropy > 7.5); // Should be close to 8

        // Repeated data should have low entropy
        let repeated_data = vec![0x42; 1000];
        let entropy = calculate_entropy(&repeated_data);
        assert!(entropy < 0.1); // Should be close to 0
    }

    #[test]
    fn test_perfect_secrecy_property() {
        // This test demonstrates that any plaintext could produce any ciphertext
        // with the appropriate key, which is the essence of perfect secrecy

        let plaintext1 = b"ATTACK!";
        let plaintext2 = b"RETREAT";
        let target_ciphertext = b"RANDOMK";

        // We can find keys that map each plaintext to the target ciphertext
        let key1: Vec<u8> = plaintext1
            .iter()
            .zip(target_ciphertext.iter())
            .map(|(p, c)| p ^ c)
            .collect();

        let key2: Vec<u8> = plaintext2
            .iter()
            .zip(target_ciphertext.iter())
            .map(|(p, c)| p ^ c)
            .collect();

        let otp1 = OneTimePad::new(key1);
        let otp2 = OneTimePad::new(key2);

        assert_eq!(
            otp1.encrypt(plaintext1).unwrap(),
            target_ciphertext.to_vec()
        );
        assert_eq!(
            otp2.encrypt(plaintext2).unwrap(),
            target_ciphertext.to_vec()
        );

        // This shows that the ciphertext reveals nothing about which plaintext was used
    }
}
