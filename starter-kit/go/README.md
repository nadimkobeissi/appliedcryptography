# Applied Cryptography Starter Kit - Go

A simple, secure, and pedagogical cryptography library for Go. This library provides high-level APIs for common cryptographic operations, designed for educational purposes.

## Features

### Hash Package (`internal/hash`)
- **SHA-2 Family**: SHA-256 and SHA-512
- **BLAKE2**: BLAKE2b-256 and BLAKE2b-512 (faster alternatives to SHA)
- **HMAC**: Message Authentication Code using BLAKE2's keyed hashing

### Encrypt Package (`internal/encrypt`)
- **AES-CTR**: Stream cipher mode for confidentiality
- **AES-GCM**: Authenticated encryption (confidentiality + authentication)
- **Additional Authenticated Data (AAD)**: Support for authenticated but unencrypted metadata

### DH Package (`internal/dh`)
- **X25519**: Elliptic curve Diffie-Hellman key agreement using Curve25519
- **Key Generation**: Secure random key pair generation
- **Shared Secret Computation**: Derive shared secrets from key exchange
- **Simple API**: Easy-to-use functions for key agreement operations

### Sign Package (`internal/sign`)
- **Ed25519**: Digital signatures using Edwards-curve Digital Signature Algorithm
- **Key Generation**: Secure random signing key pair generation
- **Signature Creation**: Sign messages with private keys
- **Signature Verification**: Verify signatures with public keys
- **Deterministic Signatures**: Same message and key always produce same signature
- **Seed-based Keys**: Support for deterministic key generation from seeds

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package tests
go test ./internal/hash
go test ./internal/encrypt
go test ./internal/dh
go test ./internal/sign
```

## Dependencies

- Go 1.25.1+
- `golang.org/x/crypto` - For BLAKE2 implementation

## License

This is educational software provided as-is for learning purposes.
