//! # Utility Functions
//!
//! This module provides common utility functions for working with
//! cryptographic data and operations.
//!
//! ## Features
//!
//! - Secure random number generation
//! - Constant-time operations
//! - Data encoding/decoding
//! - Secure memory handling
//! - Timing utilities

use crate::error::{CryptoError, Result};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Generate cryptographically secure random bytes
///
/// # Arguments
/// * `length` - Number of random bytes to generate
///
/// # Example
/// ```rust
/// use applied_crypto_starter_kit::utils::secure_random_bytes;
///
/// let random_key = secure_random_bytes(32).unwrap();
/// assert_eq!(random_key.len(), 32);
/// ```
pub fn secure_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// Generate a random u64 using system randomness
pub fn secure_random_u64() -> Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Generate random bytes in a range [min, max)
pub fn secure_random_range(min: u64, max: u64) -> Result<u64> {
    if min >= max {
        return Err(CryptoError::InvalidInput {
            reason: "min must be less than max".to_string(),
        });
    }

    let range = max - min;
    let mut value;

    // Rejection sampling to avoid bias
    loop {
        value = secure_random_u64()?;
        if value < (u64::MAX - (u64::MAX % range)) {
            return Ok(min + (value % range));
        }
    }
}

/// Constant-time comparison of byte slices
///
/// This function takes the same amount of time regardless of where
/// the first difference occurs, preventing timing attacks.
///
/// # Example
/// ```rust
/// use applied_crypto_starter_kit::utils::constant_time_compare;
///
/// let a = vec![1, 2, 3, 4];
/// let b = vec![1, 2, 3, 4];
/// assert!(constant_time_compare(&a, &b));
/// ```
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).unwrap_u8() == 1
}

/// XOR two byte arrays of equal length
///
/// # Panics
/// Panics if the arrays have different lengths
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Arrays must have equal length for XOR");

    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// XOR bytes in place
pub fn xor_bytes_inplace(target: &mut [u8], source: &[u8]) {
    assert_eq!(target.len(), source.len());

    for (t, s) in target.iter_mut().zip(source.iter()) {
        *t ^= s;
    }
}

/// Convert bytes to hex string
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| CryptoError::EncodingError {
        reason: format!("Invalid hex string: {}", e),
    })
}

/// Convert bytes to base64 string
pub fn to_base64(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}

/// Convert base64 string to bytes
pub fn from_base64(b64_str: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD
        .decode(b64_str)
        .map_err(|e| CryptoError::EncodingError {
            reason: format!("Invalid base64 string: {}", e),
        })
}

/// Secure memory wipe for sensitive data
///
/// This ensures that sensitive data is properly zeroed from memory
/// when it's no longer needed.
pub struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    /// Create new SecureBytes from a vector
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create SecureBytes with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get a reference to the data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Extend with additional bytes
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// Measure the time taken by a function
///
/// Useful for performance testing and timing attack analysis
pub fn measure_time<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    (result, duration)
}

/// Measure average time over multiple runs
pub fn measure_average_time<F>(f: F, runs: usize) -> Duration
where
    F: Fn(),
{
    let start = Instant::now();
    for _ in 0..runs {
        f();
    }
    start.elapsed() / runs as u32
}

/// Convert a u64 to 8 bytes (big-endian)
pub fn u64_to_bytes_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Convert a u64 to 8 bytes (little-endian)
pub fn u64_to_bytes_le(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Convert 8 bytes to u64 (big-endian)
pub fn bytes_to_u64_be(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 8 {
        return Err(CryptoError::InvalidInput {
            reason: "Expected 8 bytes for u64 conversion".to_string(),
        });
    }

    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(array))
}

/// Convert 8 bytes to u64 (little-endian)
pub fn bytes_to_u64_le(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 8 {
        return Err(CryptoError::InvalidInput {
            reason: "Expected 8 bytes for u64 conversion".to_string(),
        });
    }

    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(array))
}

/// Pad data to a multiple of block size using PKCS#7
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);
    padded
}

/// Remove PKCS#7 padding
pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(CryptoError::InvalidInput {
            reason: "Cannot unpad empty data".to_string(),
        });
    }

    let padding_len = data[data.len() - 1] as usize;

    if padding_len == 0 || padding_len > data.len() {
        return Err(CryptoError::InvalidInput {
            reason: "Invalid padding length".to_string(),
        });
    }

    // Verify all padding bytes are correct
    for i in 0..padding_len {
        if data[data.len() - 1 - i] != padding_len as u8 {
            return Err(CryptoError::InvalidInput {
                reason: "Invalid padding bytes".to_string(),
            });
        }
    }

    Ok(data[..data.len() - padding_len].to_vec())
}

/// Check if a number is prime (for small numbers, educational use)
#[cfg(feature = "educational")]
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }

    let sqrt_n = (n as f64).sqrt() as u64;
    for i in (3..=sqrt_n).step_by(2) {
        if n % i == 0 {
            return false;
        }
    }

    true
}

/// Generate a random prime number (small, for educational use)
#[cfg(feature = "educational")]
pub fn generate_small_prime(bits: usize) -> Result<u64> {
    if bits > 63 {
        return Err(CryptoError::InvalidInput {
            reason: "Bits must be <= 63 for u64 prime".to_string(),
        });
    }

    let min = 1u64 << (bits - 1);
    let max = (1u64 << bits) - 1;

    loop {
        let candidate = secure_random_range(min, max + 1)?;
        if is_prime(candidate) {
            return Ok(candidate);
        }
    }
}

/// Print bytes in a readable hex format
pub fn print_hex(label: &str, bytes: &[u8]) {
    println!("{}: {}", label, hex::encode(bytes));
}

/// Print bytes in hex with formatting (16 bytes per line)
pub fn print_hex_formatted(label: &str, bytes: &[u8]) {
    println!("{}:", label);
    for chunk in bytes.chunks(16) {
        print!("  ");
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        println!();
    }
}

/// Educational: Demonstrate timing differences
#[cfg(feature = "educational")]
pub fn demonstrate_timing_difference() {
    println!("\n=== Timing Difference Demo ===\n");

    let secret = vec![0x42u8; 16];
    let correct_guess = secret.clone();
    let wrong_guess = vec![0x00u8; 16];

    // Non-constant time comparison
    let (_, time_correct) = measure_time(|| {
        for _ in 0..100000 {
            let _ = secret == correct_guess;
        }
    });

    let (_, time_wrong) = measure_time(|| {
        for _ in 0..100000 {
            let _ = secret == wrong_guess;
        }
    });

    println!("Non-constant time comparison:");
    println!("  Correct guess: {:?}", time_correct);
    println!("  Wrong guess:   {:?}", time_wrong);

    // Constant time comparison
    let (_, time_correct_ct) = measure_time(|| {
        for _ in 0..100000 {
            let _ = constant_time_compare(&secret, &correct_guess);
        }
    });

    let (_, time_wrong_ct) = measure_time(|| {
        for _ in 0..100000 {
            let _ = constant_time_compare(&secret, &wrong_guess);
        }
    });

    println!("\nConstant time comparison:");
    println!("  Correct guess: {:?}", time_correct_ct);
    println!("  Wrong guess:   {:?}", time_wrong_ct);

    println!("\n📝 Constant-time operations prevent timing attacks!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_bytes() {
        let bytes1 = secure_random_bytes(32).unwrap();
        let bytes2 = secure_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different with high probability
    }

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];
        let c = vec![1, 2, 3, 4, 6];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));

        // Different lengths
        let d = vec![1, 2, 3];
        assert!(!constant_time_compare(&a, &d));
    }

    #[test]
    fn test_xor_bytes() {
        let a = vec![0xFF, 0x00, 0xAA, 0x55];
        let b = vec![0x00, 0xFF, 0x55, 0xAA];
        let result = xor_bytes(&a, &b);

        assert_eq!(result, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex_str = to_hex(&bytes);
        assert_eq!(hex_str, "deadbeef");

        let decoded = from_hex(&hex_str).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_base64_conversion() {
        let bytes = b"Hello, World!";
        let b64 = to_base64(bytes);
        let decoded = from_base64(&b64).unwrap();

        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_secure_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let mut secure = SecureBytes::new(data.clone());

        assert_eq!(secure.as_slice(), &data);
        assert_eq!(secure.len(), 5);
        assert!(!secure.is_empty());

        secure.extend_from_slice(&[6, 7, 8]);
        assert_eq!(secure.len(), 8);
    }

    #[test]
    fn test_pkcs7_padding() {
        let data = b"Hello";
        let padded = pkcs7_pad(data, 8);

        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[5..], &[3, 3, 3]);

        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_u64_conversion() {
        let value = 0x0123456789ABCDEFu64;

        let bytes_be = u64_to_bytes_be(value);
        let bytes_le = u64_to_bytes_le(value);

        assert_eq!(bytes_to_u64_be(&bytes_be).unwrap(), value);
        assert_eq!(bytes_to_u64_le(&bytes_le).unwrap(), value);

        // Big-endian and little-endian should be different
        assert_ne!(bytes_be, bytes_le);
    }

    #[test]
    #[cfg(feature = "educational")]
    fn test_is_prime() {
        assert!(!is_prime(0));
        assert!(!is_prime(1));
        assert!(is_prime(2));
        assert!(is_prime(3));
        assert!(!is_prime(4));
        assert!(is_prime(5));
        assert!(is_prime(17));
        assert!(!is_prime(100));
        assert!(is_prime(101));
    }
}
