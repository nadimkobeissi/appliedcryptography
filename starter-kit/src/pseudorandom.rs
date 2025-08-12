//! # Pseudorandom Primitives
//!
//! This module implements pseudorandom generators (PRGs), pseudorandom functions (PRFs),
//! and pseudorandom permutations (PRPs) as covered in Topic 1.4 of the course.
//!
//! ## Key Concepts
//!
//! - **PRG**: Expands a short seed into a longer pseudorandom output
//! - **PRF**: Maps inputs to pseudorandom outputs (like a keyed hash)
//! - **PRP**: A pseudorandom permutation (bijective mapping, like a block cipher)
//!
//! ## Security Properties
//!
//! These primitives are computationally indistinguishable from their truly random
//! counterparts to any polynomial-time adversary.

use crate::error::{CryptoError, Result};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac as HmacTrait};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A pseudorandom generator that expands a seed into a longer output
///
/// # Example
/// ```rust
/// use applied_crypto_starter_kit::pseudorandom::PseudorandomGenerator;
///
/// let seed = [42u8; 32];
/// let mut prg = PseudorandomGenerator::from_seed(seed);
/// let output = prg.generate(128); // Generate 128 pseudorandom bytes
/// ```
pub struct PseudorandomGenerator {
    seed: [u8; 32],
    counter: u64,
}

impl PseudorandomGenerator {
    /// Create a new PRG from a 256-bit seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    /// Generate pseudorandom bytes
    ///
    /// # Arguments
    /// * `length` - Number of bytes to generate
    ///
    /// # Returns
    /// A vector of pseudorandom bytes
    pub fn generate(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);

        while output.len() < length {
            // Use SHA-256 in counter mode as a PRG
            let mut hasher = Sha256::new();
            hasher.update(&self.seed);
            hasher.update(&self.counter.to_be_bytes());
            let hash = hasher.finalize();

            let remaining = length - output.len();
            if remaining >= 32 {
                output.extend_from_slice(&hash);
            } else {
                output.extend_from_slice(&hash[..remaining]);
            }

            self.counter += 1;
        }

        output
    }

    /// Generate the next pseudorandom u64
    pub fn next_u64(&mut self) -> u64 {
        let bytes = self.generate(8);
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    /// Double the length of input using the PRG (length-doubling PRG)
    ///
    /// This is a fundamental construction in theoretical cryptography
    pub fn double_length(seed: &[u8]) -> Result<Vec<u8>> {
        if seed.len() != 16 {
            return Err(CryptoError::InvalidInput {
                reason: "Seed must be 16 bytes for length doubling".to_string(),
            });
        }

        // Use SHA-256 to double the length
        let mut output = Vec::with_capacity(32);

        // Generate left half using domain separation
        let mut hasher = Sha256::new();
        hasher.update(&[0u8]); // Domain separator for left half
        hasher.update(seed);
        let left = hasher.finalize();
        output.extend_from_slice(&left[..16]);

        // Generate right half using domain separation
        let mut hasher = Sha256::new();
        hasher.update(&[1u8]); // Domain separator for right half
        hasher.update(seed);
        let right = hasher.finalize();
        output.extend_from_slice(&right[..16]);

        Ok(output)
    }
}

/// A pseudorandom function implementation using HMAC
///
/// PRFs map inputs to pseudorandom outputs that appear random to anyone
/// without the key, but are deterministic given the key.
pub struct PseudorandomFunction {
    key: Vec<u8>,
}

impl PseudorandomFunction {
    /// Create a new PRF with the given key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Evaluate the PRF on an input
    ///
    /// # Arguments
    /// * `input` - The input to the PRF
    ///
    /// # Returns
    /// The pseudorandom output (32 bytes for HMAC-SHA256)
    pub fn evaluate(&self, input: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(&self.key)
            .expect("HMAC can accept any key size");
        mac.update(input);
        mac.finalize().into_bytes().to_vec()
    }

    /// Generate a PRF output with a specific output length using counter mode
    ///
    /// This is similar to HKDF-Expand but simpler for educational purposes
    pub fn evaluate_with_length(&self, input: &[u8], output_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut counter = 0u32;

        while output.len() < output_len {
            let mut mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(&self.key)
                .expect("HMAC can accept any key size");
            mac.update(input);
            mac.update(&counter.to_be_bytes());

            let hash = mac.finalize().into_bytes();
            let remaining = output_len - output.len();
            if remaining >= 32 {
                output.extend_from_slice(&hash);
            } else {
                output.extend_from_slice(&hash[..remaining]);
            }

            counter += 1;
        }

        output
    }
}

/// A pseudorandom permutation (block cipher) implementation
///
/// PRPs are bijective functions that appear random but are invertible with the key.
/// This uses AES-256 as the underlying PRP.
pub struct PseudorandomPermutation {
    cipher: Aes256,
}

impl PseudorandomPermutation {
    /// Create a new PRP with a 256-bit key
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256::new(&key.into()),
        }
    }

    /// Apply the permutation (encrypt a block)
    ///
    /// # Arguments
    /// * `block` - A 16-byte block to permute
    ///
    /// # Returns
    /// The permuted block
    pub fn permute(&self, block: [u8; 16]) -> [u8; 16] {
        let mut output = block.into();
        self.cipher.encrypt_block(&mut output);
        output.into()
    }

    /// Apply the inverse permutation (decrypt a block)
    ///
    /// Note: This would require the decryption implementation for AES.
    /// For educational purposes, we're focusing on the forward direction.
    pub fn inverse_permute(&self, _block: [u8; 16]) -> Result<[u8; 16]> {
        Err(CryptoError::NotSupported {
            reason: "Inverse permutation not implemented in this educational example".to_string(),
        })
    }
}

/// The GGM (Goldreich-Goldwasser-Micali) construction
///
/// This builds a PRF from a length-doubling PRG, demonstrating a fundamental
/// theoretical construction in cryptography.
pub struct GGMConstruction {
    seed: [u8; 16],
}

impl GGMConstruction {
    /// Create a new GGM PRF from a seed
    pub fn new(seed: [u8; 16]) -> Self {
        Self { seed }
    }

    /// Evaluate the GGM PRF on an n-bit input
    ///
    /// # Arguments
    /// * `input_bits` - A vector of booleans representing the input bits
    ///
    /// # Returns
    /// The PRF output (16 bytes)
    pub fn evaluate(&self, input_bits: &[bool]) -> Result<Vec<u8>> {
        let mut current = self.seed.to_vec();

        for &bit in input_bits {
            // Double the length using our PRG
            let expanded = PseudorandomGenerator::double_length(&current)?;

            // Take left or right half based on input bit
            current = if bit {
                expanded[16..32].to_vec() // Right half
            } else {
                expanded[..16].to_vec() // Left half
            };
        }

        Ok(current)
    }
}

/// Demonstrates the PRF-PRP Switching Lemma
///
/// This shows that for a small number of queries, a PRP is indistinguishable from a PRF
pub struct PRFPRPSwitching {
    /// Track PRP outputs to detect collisions (though PRP won't have collisions)
    prp_outputs: HashMap<Vec<u8>, Vec<u8>>,
    /// Track PRF outputs
    prf_outputs: HashMap<Vec<u8>, Vec<u8>>,
}

impl PRFPRPSwitching {
    /// Create a new switching lemma demonstrator
    pub fn new() -> Self {
        Self {
            prp_outputs: HashMap::new(),
            prf_outputs: HashMap::new(),
        }
    }

    /// Simulate q queries and calculate collision probability
    ///
    /// The PRP-PRF distinguishing advantage is bounded by q²/2^(n+1) where n is the block size in bits
    pub fn demonstrate_switching_lemma(&mut self, num_queries: usize) -> f64 {
        let key = [0x42u8; 32];
        let prp = PseudorandomPermutation::new(key);
        let prf = PseudorandomFunction::new(key.to_vec());

        let mut collisions = 0;
        self.prp_outputs.clear();
        self.prf_outputs.clear();

        for i in 0..num_queries {
            // Create a unique input for each query
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&(i as u64).to_be_bytes());

            // PRP output (guaranteed no collisions as it's a permutation)
            let prp_out = prp.permute(input);

            // PRF output (might have collisions) - truncate to 16 bytes for fair comparison
            let prf_full = prf.evaluate(&input);
            let mut prf_out = [0u8; 16];
            prf_out.copy_from_slice(&prf_full[..16]);

            // Check for collisions in PRF outputs
            if self.prf_outputs.values().any(|v| v[..16] == prf_out) {
                collisions += 1;
            }

            self.prp_outputs.insert(input.to_vec(), prp_out.to_vec());
            self.prf_outputs.insert(input.to_vec(), prf_out.to_vec());
        }

        // Return collision rate (not probability)
        collisions as f64 / num_queries as f64
    }

    /// Calculate theoretical bound for PRP-PRF distinguishing advantage
    ///
    /// The advantage is bounded by q(q-1)/2^(n+1) where q is the number of queries
    /// and n is the block size in bits
    pub fn theoretical_bound(num_queries: usize, block_size_bits: usize) -> f64 {
        let q = num_queries as f64;
        let two_to_n = 2_f64.powi(block_size_bits as i32);

        // The exact bound is q(q-1)/2^(n+1)
        (q * (q - 1.0)) / (2.0 * two_to_n)
    }
}

/// Demonstrate that PRGs can be distinguished from random with enough output
#[cfg(feature = "educational")]
pub fn demonstrate_prg_period() {
    println!("\n=== PRG Period Demonstration ===\n");

    // Even good PRGs have a period (they eventually repeat)
    // though for cryptographic PRGs this period is astronomically large

    let seed = [0u8; 32];
    let mut prg = PseudorandomGenerator::from_seed(seed);

    println!("Generating pseudorandom values from a fixed seed:");
    for i in 0..5 {
        println!("  Value {}: {}", i, prg.next_u64());
    }

    // Reset with same seed
    let mut prg2 = PseudorandomGenerator::from_seed(seed);
    println!("\nSame seed produces same sequence:");
    for i in 0..5 {
        println!("  Value {}: {}", i, prg2.next_u64());
    }

    println!("\n📝 PRGs are deterministic - same seed always produces same output!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prg_deterministic() {
        let seed = [42u8; 32];
        let mut prg1 = PseudorandomGenerator::from_seed(seed);
        let mut prg2 = PseudorandomGenerator::from_seed(seed);

        assert_eq!(prg1.generate(100), prg2.generate(100));
    }

    #[test]
    fn test_prg_different_seeds() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let mut prg1 = PseudorandomGenerator::from_seed(seed1);
        let mut prg2 = PseudorandomGenerator::from_seed(seed2);

        assert_ne!(prg1.generate(100), prg2.generate(100));
    }

    #[test]
    fn test_prf_deterministic() {
        let key = vec![0x42; 32];
        let prf = PseudorandomFunction::new(key);

        let input = b"test input";
        let output1 = prf.evaluate(input);
        let output2 = prf.evaluate(input);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_prf_different_inputs() {
        let key = vec![0x42; 32];
        let prf = PseudorandomFunction::new(key);

        let output1 = prf.evaluate(b"input1");
        let output2 = prf.evaluate(b"input2");

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_prp_permutation() {
        let key = [0x42u8; 32];
        let prp = PseudorandomPermutation::new(key);

        let block1 = [1u8; 16];
        let block2 = [2u8; 16];

        let output1 = prp.permute(block1);
        let output2 = prp.permute(block2);

        // Different inputs should give different outputs (bijection property)
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_ggm_construction() {
        let seed = [0x42u8; 16];
        let ggm = GGMConstruction::new(seed);

        let input1 = vec![false, true, false]; // 010
        let input2 = vec![false, true, true]; // 011

        let output1 = ggm.evaluate(&input1).unwrap();
        let output2 = ggm.evaluate(&input2).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_prf_prp_switching() {
        let mut switcher = PRFPRPSwitching::new();

        // With few queries, PRP and PRF are hard to distinguish
        let collision_rate = switcher.demonstrate_switching_lemma(10);
        let theoretical = PRFPRPSwitching::theoretical_bound(10, 128);

        // Collision rate should be very small for few queries
        assert!(collision_rate < 0.1);
        println!(
            "Collision rate: {}, Theoretical bound: {}",
            collision_rate, theoretical
        );
    }

    #[test]
    fn test_length_doubling_prg() {
        let seed = [0x42u8; 16];
        let output = PseudorandomGenerator::double_length(&seed).unwrap();

        assert_eq!(output.len(), 32);
        assert_ne!(&output[..16], &output[16..]); // Two halves should be different
    }
}
