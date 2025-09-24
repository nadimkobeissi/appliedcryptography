package hash_test

import (
	"encoding/hex"
	"fmt"

	"appliedcryptography-starter-kit/internal/hash"
)

func ExampleSHA256() {
	data := []byte("Hello, World!")
	hashValue := hash.SHA256(data)

	fmt.Printf("SHA-256: %s\n", hex.EncodeToString(hashValue))
	fmt.Printf("Length: %d bytes\n", len(hashValue))
	// Output:
	// SHA-256: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
	// Length: 32 bytes
}

func ExampleSHA512() {
	data := []byte("Hello, World!")
	hashValue := hash.SHA512(data)

	fmt.Printf("SHA-512: %s\n", hex.EncodeToString(hashValue))
	fmt.Printf("Length: %d bytes\n", len(hashValue))
	// Output:
	// SHA-512: 374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387
	// Length: 64 bytes
}

func ExampleBLAKE2b256() {
	data := []byte("Hello, World!")
	hashValue, err := hash.BLAKE2b256(data)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("BLAKE2b-256: %s\n", hex.EncodeToString(hashValue))
	fmt.Printf("Length: %d bytes\n", len(hashValue))
	// Output:
	// BLAKE2b-256: 511bc81dde11180838c562c82bb35f3223f46061ebde4a955c27b3f489cf1e03
	// Length: 32 bytes
}

func ExampleBLAKE2b512() {
	data := []byte("Hello, World!")
	hashValue, err := hash.BLAKE2b512(data)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("BLAKE2b-512: %s\n", hex.EncodeToString(hashValue))
	fmt.Printf("Length: %d bytes\n", len(hashValue))

	// Output:
	// BLAKE2b-512: 7dfdb888af71eae0e6a6b751e8e3413d767ef4fa52a7993daa9ef097f7aa3d949199c113caa37c94f80cf3b22f7d9d6e4f5def4ff927830cffe4857c34be3d89
	// Length: 64 bytes
}

func ExampleHMAC() {
	key := []byte("my-secret-key")
	message := []byte("Important message")

	mac, err := hash.HMAC(key, message)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("MAC: %s\n", hex.EncodeToString(mac))
	fmt.Printf("Length: %d bytes\n", len(mac))

	// Output:
	// MAC: 56b073c6a452cba9b3804bfb49a5e6caac3217c8fead778ca10cf340ec1cb875
	// Length: 32 bytes

}

func ExampleVerifyMAC() {
	key := []byte("my-secret-key")
	message := []byte("Important message")

	// Generate MAC
	mac, err := hash.HMAC(key, message)
	if err != nil {
		fmt.Printf("Error generating MAC: %v\n", err)
		return
	}

	// Verify with correct MAC
	valid, err := hash.VerifyMAC(key, message, mac)
	if err != nil {
		fmt.Printf("Error verifying MAC: %v\n", err)
		return
	}
	fmt.Printf("Valid MAC: %v\n", valid)

	// Verify with incorrect MAC (simulated)
	wrongMAC := make([]byte, len(mac))
	copy(wrongMAC, mac)
	wrongMAC[0] ^= 0xFF // Flip bits to make it wrong

	valid, err = hash.VerifyMAC(key, message, wrongMAC)
	if err != nil {
		fmt.Printf("Error verifying MAC: %v\n", err)
		return
	}
	fmt.Printf("Invalid MAC: %v\n", valid)
	// Output:
	// Valid MAC: true
	// Invalid MAC: false
}

func ExampleScrypt() {
	password := []byte("Hello Suleiman")
	salt := []byte("Hello carl")
	N, r, p := 16384, 8, 1
	keyLen := 64

	dk, err := hash.Scrypt(password, salt, N, r, p, keyLen)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Derived key: %s\n", hex.EncodeToString(dk))
	fmt.Printf("Length: %d bytes\n", len(dk))
	// Output:
	// Derived key: e4549587a6c797df0599a2afaa2fce5ef5f7564b8748da510924c178260df465a09fd941b5268ca9f5f079fa6e1d7c8c7bedce90c27de504fc00a5eb521ebb34
	// Length: 64 bytes
}

func ExampleScryptDefault() {
	password := []byte("AUB-Password(Important)")
	salt := []byte("AUB-Salt(Also important)")
	dk, err := hash.ScryptDefault(password, salt)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Length: %d bytes\n", len(dk))
	// Output:
	// Length: 32 bytes
}
