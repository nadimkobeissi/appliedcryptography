//! Error types for the Applied Cryptography Starter Kit
//!
//! This module defines the various error conditions that can occur
//! when working with cryptographic primitives.

use thiserror::Error;

/// Main error type for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid key size for the algorithm
    #[error("Invalid key size: expected {expected} bytes, got {actual} bytes")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size provided
        actual: usize,
    },

    /// Invalid nonce or IV size
    #[error("Invalid nonce/IV size: expected {expected} bytes, got {actual} bytes")]
    InvalidNonceSize {
        /// Expected nonce size in bytes
        expected: usize,
        /// Actual nonce size provided
        actual: usize,
    },

    /// Invalid secret key
    #[error("Invalid secret key: {reason}")]
    InvalidSecretKey {
        /// Reason why secret key is invalid
        reason: String,
    },

    /// Invalid block size for block cipher operations
    #[error("Invalid block size: data length {length} is not a multiple of {block_size}")]
    InvalidBlockSize {
        /// Data length
        length: usize,
        /// Required block size
        block_size: usize,
    },

    /// Decryption failed (e.g., authentication tag mismatch)
    #[error("Decryption failed: {reason}")]
    DecryptionFailed {
        /// Reason for decryption failure
        reason: String,
    },

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid signature format
    #[error("Invalid signature format: {reason}")]
    InvalidSignature {
        /// Reason why signature format is invalid
        reason: String,
    },

    /// Invalid public key
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey {
        /// Reason why public key is invalid
        reason: String,
    },

    /// Invalid private key
    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey {
        /// Reason why private key is invalid
        reason: String,
    },

    /// Hash function error
    #[error("Hash function error: {reason}")]
    HashError {
        /// Reason for hash error
        reason: String,
    },

    /// Random number generation failed
    #[error("Random number generation failed: {reason}")]
    RandomGenerationFailed {
        /// Reason for RNG failure
        reason: String,
    },

    /// Invalid input data
    #[error("Invalid input: {reason}")]
    InvalidInput {
        /// Reason why input is invalid
        reason: String,
    },

    /// Operation not supported
    #[error("Operation not supported: {reason}")]
    NotSupported {
        /// Reason why operation is not supported
        reason: String,
    },

    /// Buffer too small for operation
    #[error("Buffer too small: need at least {required} bytes, got {actual} bytes")]
    BufferTooSmall {
        /// Required buffer size
        required: usize,
        /// Actual buffer size
        actual: usize,
    },

    /// Key derivation failed
    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// Reason for KDF failure
        reason: String,
    },

    /// MAC verification failed
    #[error("MAC verification failed")]
    MacVerificationFailed,

    /// Invalid curve point
    #[error("Invalid curve point: {reason}")]
    InvalidCurvePoint {
        /// Reason why curve point is invalid
        reason: String,
    },

    /// Diffie-Hellman error
    #[error("Diffie-Hellman error: {reason}")]
    DiffieHellmanError {
        /// Reason for DH error
        reason: String,
    },

    /// Encoding/Decoding error
    #[error("Encoding error: {reason}")]
    EncodingError {
        /// Reason for encoding error
        reason: String,
    },

    /// Generic cryptographic error
    #[error("Cryptographic error: {0}")]
    Generic(String),

    /// Wrapped error from external library
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result type alias for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

// Implement conversions from common external error types

impl From<hex::FromHexError> for CryptoError {
    fn from(err: hex::FromHexError) -> Self {
        CryptoError::EncodingError {
            reason: format!("Hex decoding error: {}", err),
        }
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::EncodingError {
            reason: format!("Base64 decoding error: {}", err),
        }
    }
}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        CryptoError::RandomGenerationFailed {
            reason: format!("System RNG error: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidKeySize {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            err.to_string(),
            "Invalid key size: expected 32 bytes, got 16 bytes"
        );
    }

    #[test]
    fn test_result_type() {
        fn example_function() -> Result<u32> {
            Ok(42)
        }
        assert_eq!(example_function().unwrap(), 42);
    }
}
