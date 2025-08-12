//! # Symmetric Encryption
//!
//! This module implements various block cipher modes of operation as covered
//! in Topic 1.5 of the Applied Cryptography course.
//!
//! ## Block Cipher Modes
//!
//! - **ECB (Electronic Codebook)**: Insecure, demonstrates why deterministic encryption fails
//! - **CBC (Cipher Block Chaining)**: CPA-secure with random IV
//! - **CTR (Counter Mode)**: Converts block cipher to stream cipher, CPA-secure
//! - **GCM (Galois/Counter Mode)**: Authenticated encryption (CCA-secure)
//!
//! ## Security Levels
//!
//! - **CPA Security**: Secure against chosen-plaintext attacks
//! - **CCA Security**: Secure against chosen-ciphertext attacks

use crate::error::{CryptoError, Result};
use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac as HmacTrait};
use sha2::Sha256;

/// Block size for AES in bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// ECB (Electronic Codebook) mode - INSECURE, for educational purposes only
///
/// ECB mode encrypts each block independently, making it vulnerable to
/// pattern analysis attacks.
pub mod ecb {
    use super::*;

    /// Encrypt using ECB mode (INSECURE - educational only)
    ///
    /// # Security Warning
    /// ECB mode is deterministic and reveals patterns in the plaintext.
    /// NEVER use this in production!
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() % AES_BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidBlockSize {
                length: plaintext.len(),
                block_size: AES_BLOCK_SIZE,
            });
        }

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut ciphertext = plaintext.to_vec();

        for chunk in ciphertext.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(&mut block);
        }

        Ok(ciphertext)
    }

    /// Decrypt using ECB mode
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidBlockSize {
                length: ciphertext.len(),
                block_size: AES_BLOCK_SIZE,
            });
        }

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let decrypt_cipher = unsafe {
            // Creating decryption cipher - in real code use proper decrypt setup
            std::mem::transmute::<Aes256, Aes256>(cipher)
        };

        let mut plaintext = ciphertext.to_vec();

        for chunk in plaintext.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut block = GenericArray::from_mut_slice(chunk);
            decrypt_cipher.decrypt_block(&mut block);
        }

        Ok(plaintext)
    }

    /// Demonstrate why ECB mode is insecure
    #[cfg(feature = "educational")]
    pub fn demonstrate_ecb_vulnerability() {
        println!("\n=== ECB Mode Vulnerability Demo ===\n");

        let key = [0x42u8; 32];

        // Create a message with repeated blocks
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(b"SAME_BLOCK_16BYT");
        plaintext.extend_from_slice(b"DIFFERENT_BLOCK!");
        plaintext.extend_from_slice(b"SAME_BLOCK_16BYT"); // Repeated block

        let ciphertext = encrypt(&key, &plaintext).unwrap();

        println!("Plaintext blocks:");
        for (i, chunk) in plaintext.chunks(16).enumerate() {
            println!("  Block {}: {:?}", i, std::str::from_utf8(chunk).unwrap());
        }

        println!("\nCiphertext blocks (hex):");
        for (i, chunk) in ciphertext.chunks(16).enumerate() {
            println!("  Block {}: {}", i, hex::encode(chunk));
        }

        println!("\n⚠️  Notice: Blocks 0 and 2 have identical ciphertext!");
        println!("This reveals that the plaintext blocks are the same!");
    }
}

/// CBC (Cipher Block Chaining) mode - CPA-secure
pub mod cbc {
    use super::*;

    /// Encrypt using CBC mode with a random IV
    ///
    /// # Returns
    /// The ciphertext with IV prepended (IV || Ciphertext)
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Apply PKCS#7 padding
        let padded = pkcs7_pad(plaintext);

        // Generate random IV
        let mut iv = [0u8; AES_BLOCK_SIZE];
        getrandom::fill(&mut iv)?;

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut ciphertext = Vec::with_capacity(AES_BLOCK_SIZE + padded.len());
        ciphertext.extend_from_slice(&iv);

        let mut prev_block = iv;

        for chunk in padded.chunks_exact(AES_BLOCK_SIZE) {
            // XOR with previous ciphertext block
            let mut block = [0u8; AES_BLOCK_SIZE];
            for i in 0..AES_BLOCK_SIZE {
                block[i] = chunk[i] ^ prev_block[i];
            }

            let mut block_array = GenericArray::from_slice(&block).clone();
            cipher.encrypt_block(&mut block_array);

            ciphertext.extend_from_slice(&block_array);
            prev_block.copy_from_slice(&block_array);
        }

        Ok(ciphertext)
    }

    /// Decrypt CBC mode ciphertext
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext with IV prepended
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < AES_BLOCK_SIZE || ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidInput {
                reason: "Invalid ciphertext length".to_string(),
            });
        }

        let iv = &ciphertext[..AES_BLOCK_SIZE];
        let encrypted = &ciphertext[AES_BLOCK_SIZE..];

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let decrypt_cipher = unsafe { std::mem::transmute::<Aes256, Aes256>(cipher) };

        let mut plaintext = Vec::new();
        let mut prev_block = iv;

        for chunk in encrypted.chunks_exact(AES_BLOCK_SIZE) {
            let mut block = GenericArray::from_slice(chunk).clone();
            decrypt_cipher.decrypt_block(&mut block);

            // XOR with previous ciphertext block
            for i in 0..AES_BLOCK_SIZE {
                block[i] ^= prev_block[i];
            }

            plaintext.extend_from_slice(&block);
            prev_block = chunk;
        }

        // Remove padding
        pkcs7_unpad(&plaintext)
    }
}

/// CTR (Counter) mode - Converts block cipher to stream cipher
pub mod ctr {
    use super::*;

    /// Encrypt using CTR mode with a random nonce
    ///
    /// # Returns
    /// The ciphertext with nonce prepended (Nonce || Ciphertext)
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce (96 bits for CTR)
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce)?;

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut ciphertext = Vec::with_capacity(12 + plaintext.len());
        ciphertext.extend_from_slice(&nonce);

        // Counter starts at 0
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(&nonce);

        let mut remaining = plaintext;
        let mut block_num = 0u32;

        while !remaining.is_empty() {
            // Set counter value
            counter[12..].copy_from_slice(&block_num.to_be_bytes());

            // Encrypt counter
            let mut keystream_block = GenericArray::from_slice(&counter).clone();
            cipher.encrypt_block(&mut keystream_block);

            // XOR with plaintext
            let chunk_len = remaining.len().min(AES_BLOCK_SIZE);
            for i in 0..chunk_len {
                ciphertext.push(remaining[i] ^ keystream_block[i]);
            }

            remaining = &remaining[chunk_len..];
            block_num += 1;
        }

        Ok(ciphertext)
    }

    /// Decrypt CTR mode ciphertext
    ///
    /// Note: In CTR mode, decryption is identical to encryption
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::InvalidInput {
                reason: "Ciphertext too short".to_string(),
            });
        }

        let nonce = &ciphertext[..12];
        let encrypted = &ciphertext[12..];

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut plaintext = Vec::with_capacity(encrypted.len());

        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);

        let mut remaining = encrypted;
        let mut block_num = 0u32;

        while !remaining.is_empty() {
            counter[12..].copy_from_slice(&block_num.to_be_bytes());

            let mut keystream_block = GenericArray::from_slice(&counter).clone();
            cipher.encrypt_block(&mut keystream_block);

            let chunk_len = remaining.len().min(AES_BLOCK_SIZE);
            for i in 0..chunk_len {
                plaintext.push(remaining[i] ^ keystream_block[i]);
            }

            remaining = &remaining[chunk_len..];
            block_num += 1;
        }

        Ok(plaintext)
    }
}

/// AES-CTR mode using the ctr crate (more efficient implementation)
pub mod aes_ctr {
    use super::*;
    use ::ctr::Ctr128BE;
    use ::ctr::cipher::{KeyIvInit, StreamCipher};

    type Aes256Ctr = Ctr128BE<Aes256>;

    /// Encrypt using AES-256-CTR
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)?;

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(&nonce),
        );

        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Prepend nonce
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt using AES-256-CTR
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::InvalidInput {
                reason: "Ciphertext too short".to_string(),
            });
        }

        let nonce = &ciphertext[..16];
        let encrypted = &ciphertext[16..];

        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(nonce),
        );

        let mut plaintext = encrypted.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

/// AES-GCM (Galois/Counter Mode) - Authenticated encryption (CCA-secure)
pub mod aes_gcm {
    use super::*;
    use ::aes_gcm::aead::generic_array::GenericArray as AeadGenericArray;
    use ::aes_gcm::{
        Aes256Gcm,
        aead::{Aead, KeyInit as AeadKeyInit, Payload},
    };

    /// GCM nonce size in bytes (96 bits)
    pub const GCM_NONCE_SIZE: usize = 12;
    /// GCM authentication tag size in bytes (128 bits)
    pub const GCM_TAG_SIZE: usize = 16;

    /// Encrypt using AES-256-GCM with optional associated data
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Optional associated authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    /// The ciphertext with nonce prepended (Nonce || Ciphertext || Tag)
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        getrandom::fill(&mut nonce)?;

        let cipher = Aes256Gcm::new(AeadGenericArray::from_slice(key));

        let payload = match aad {
            Some(aad_data) => Payload {
                msg: plaintext,
                aad: aad_data,
            },
            None => Payload::from(plaintext),
        };

        let ciphertext = cipher
            .encrypt(AeadGenericArray::from_slice(&nonce), payload)
            .map_err(|e| CryptoError::Generic(format!("GCM encryption failed: {}", e)))?;

        // Return Nonce || Ciphertext (which includes the tag)
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt and verify AES-256-GCM ciphertext
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `ciphertext` - The ciphertext with nonce prepended
    /// * `aad` - Optional associated authenticated data (must match encryption AAD)
    ///
    /// # Returns
    /// The decrypted plaintext if authentication succeeds
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if ciphertext.len() < GCM_NONCE_SIZE + GCM_TAG_SIZE {
            return Err(CryptoError::InvalidInput {
                reason: "Ciphertext too short for GCM".to_string(),
            });
        }

        let nonce = &ciphertext[..GCM_NONCE_SIZE];
        let encrypted_with_tag = &ciphertext[GCM_NONCE_SIZE..];

        let cipher = Aes256Gcm::new(AeadGenericArray::from_slice(key));

        let payload = match aad {
            Some(aad_data) => Payload {
                msg: encrypted_with_tag,
                aad: aad_data,
            },
            None => Payload::from(encrypted_with_tag),
        };

        cipher
            .decrypt(AeadGenericArray::from_slice(nonce), payload)
            .map_err(|_| CryptoError::MacVerificationFailed)
    }

    /// Encrypt using AES-256-GCM without associated data
    pub fn encrypt_simple(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt(key, plaintext, None)
    }

    /// Decrypt using AES-256-GCM without associated data
    pub fn decrypt_simple(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt(key, ciphertext, None)
    }
}

/// Encrypt-then-MAC for CCA security
pub struct AuthenticatedEncryption {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl AuthenticatedEncryption {
    /// Create a new authenticated encryption instance
    pub fn new(enc_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self { enc_key, mac_key }
    }

    /// Encrypt and authenticate a message
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Encrypt using CTR mode
        let ciphertext = aes_ctr::encrypt(&self.enc_key, plaintext)?;

        // Compute MAC over ciphertext
        let mut mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(&self.mac_key)
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        // Return Ciphertext || MAC
        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }

    /// Verify and decrypt a message
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 32 {
            return Err(CryptoError::InvalidInput {
                reason: "Ciphertext too short for MAC".to_string(),
            });
        }

        let (encrypted, received_tag) = ciphertext.split_at(ciphertext.len() - 32);

        // Verify MAC
        let mut mac = <Hmac<Sha256> as HmacTrait>::new_from_slice(&self.mac_key)
            .map_err(|e| CryptoError::Generic(e.to_string()))?;
        mac.update(encrypted);

        mac.verify_slice(received_tag)
            .map_err(|_| CryptoError::MacVerificationFailed)?;

        // Decrypt if MAC is valid
        aes_ctr::decrypt(&self.enc_key, encrypted)
    }
}

/// PKCS#7 padding
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let padding_len = AES_BLOCK_SIZE - (data.len() % AES_BLOCK_SIZE);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);
    padded
}

/// Remove PKCS#7 padding
fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(CryptoError::InvalidInput {
            reason: "Empty data for unpadding".to_string(),
        });
    }

    let padding_len = data[data.len() - 1] as usize;

    if padding_len == 0 || padding_len > AES_BLOCK_SIZE || padding_len > data.len() {
        return Err(CryptoError::InvalidInput {
            reason: "Invalid padding".to_string(),
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

/// Demonstrate malleability of CTR mode (why we need authentication)
#[cfg(feature = "educational")]
pub fn demonstrate_ctr_malleability() {
    println!("\n=== CTR Mode Malleability Demo ===\n");

    let key = [0x42u8; 32];
    let plaintext = b"Transfer $100 to Alice";

    let ciphertext = aes_ctr::encrypt(&key, plaintext).unwrap();
    println!(
        "Original plaintext: {:?}",
        std::str::from_utf8(plaintext).unwrap()
    );

    // Attacker flips bits in ciphertext to change the amount
    let mut modified = ciphertext.clone();
    // This would flip specific bits to change "100" to something else
    modified[26] ^= 0x06; // Flip a bit in the amount

    let decrypted = aes_ctr::decrypt(&key, &modified).unwrap();
    println!(
        "Modified plaintext: {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    println!("\n⚠️  CTR mode is malleable - attackers can flip bits!");
    println!("This is why we need authenticated encryption (CCA security)!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, CBC mode encryption!";

        let ciphertext = cbc::encrypt(&key, plaintext).unwrap();
        let decrypted = cbc::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_ctr_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, CTR mode! This can be any length.";

        let ciphertext = ctr::encrypt(&key, plaintext).unwrap();
        let decrypted = ctr::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, GCM mode! Authenticated encryption.";

        let ciphertext = aes_gcm::encrypt_simple(&key, plaintext).unwrap();
        let decrypted = aes_gcm::decrypt_simple(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_gcm_with_aad() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret message";
        let aad = b"Additional authenticated data";

        let ciphertext = aes_gcm::encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = aes_gcm::decrypt(&key, &ciphertext, Some(aad)).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_gcm_tamper_detection() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret authenticated message";

        let mut ciphertext = aes_gcm::encrypt_simple(&key, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[20] ^= 0xFF;

        // Decryption should fail due to authentication failure
        assert!(aes_gcm::decrypt_simple(&key, &ciphertext).is_err());
    }

    #[test]
    fn test_gcm_wrong_aad() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret message";
        let aad = b"Correct AAD";
        let wrong_aad = b"Wrong AAD";

        let ciphertext = aes_gcm::encrypt(&key, plaintext, Some(aad)).unwrap();

        // Decryption with wrong AAD should fail
        assert!(aes_gcm::decrypt(&key, &ciphertext, Some(wrong_aad)).is_err());
    }

    #[test]
    fn test_authenticated_encryption() {
        let enc_key = [0x01u8; 32];
        let mac_key = [0x02u8; 32];

        let ae = AuthenticatedEncryption::new(enc_key, mac_key);
        let plaintext = b"Secret authenticated message";

        let ciphertext = ae.encrypt(plaintext).unwrap();
        let decrypted = ae.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_authenticated_encryption_tamper_detection() {
        let enc_key = [0x01u8; 32];
        let mac_key = [0x02u8; 32];

        let ae = AuthenticatedEncryption::new(enc_key, mac_key);
        let plaintext = b"Secret authenticated message";

        let mut ciphertext = ae.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[10] ^= 0xFF;

        // Decryption should fail due to MAC mismatch
        assert!(ae.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_pkcs7_padding() {
        let data = b"Hello";
        let padded = pkcs7_pad(data);
        assert_eq!(padded.len(), 16);

        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }
}
