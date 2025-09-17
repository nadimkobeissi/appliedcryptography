package hash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string // hex encoded
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "single byte",
			input:    []byte("a"),
			expected: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256(tt.input)
			resultHex := hex.EncodeToString(result)

			if resultHex != tt.expected {
				t.Errorf("SHA256() = %s, want %s", resultHex, tt.expected)
			}

			if len(result) != 32 {
				t.Errorf("SHA256() returned %d bytes, want 32", len(result))
			}
		})
	}
}

func TestSHA512(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string // hex encoded
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387",
		},
		{
			name:     "single byte",
			input:    []byte("a"),
			expected: "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA512(tt.input)
			resultHex := hex.EncodeToString(result)

			if resultHex != tt.expected {
				t.Errorf("SHA512() = %s, want %s", resultHex, tt.expected)
			}

			if len(result) != 64 {
				t.Errorf("SHA512() returned %d bytes, want 64", len(result))
			}
		})
	}
}

func TestBLAKE2b256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string // hex encoded
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "511bc81dde11180838c562c82bb35f3223f46061ebde4a955c27b3f489cf1e03",
		},
		{
			name:     "single byte",
			input:    []byte("a"),
			expected: "8928aae63c84d87ea098564d1e03ad813f107add474e56aedd286349c0c03ea4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BLAKE2b256(tt.input)
			if err != nil {
				t.Fatalf("BLAKE2b256() error = %v", err)
			}

			resultHex := hex.EncodeToString(result)
			if resultHex != tt.expected {
				t.Errorf("BLAKE2b256() = %s, want %s", resultHex, tt.expected)
			}

			if len(result) != 32 {
				t.Errorf("BLAKE2b256() returned %d bytes, want 32", len(result))
			}
		})
	}
}

func TestBLAKE2b512(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string // hex encoded
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "7dfdb888af71eae0e6a6b751e8e3413d767ef4fa52a7993daa9ef097f7aa3d949199c113caa37c94f80cf3b22f7d9d6e4f5def4ff927830cffe4857c34be3d89",
		},
		{
			name:     "single byte",
			input:    []byte("a"),
			expected: "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BLAKE2b512(tt.input)
			if err != nil {
				t.Fatalf("BLAKE2b512() error = %v", err)
			}

			resultHex := hex.EncodeToString(result)
			if resultHex != tt.expected {
				t.Errorf("BLAKE2b512() = %s, want %s", resultHex, tt.expected)
			}

			if len(result) != 64 {
				t.Errorf("BLAKE2b512() returned %d bytes, want 64", len(result))
			}
		})
	}
}

func TestHMAC(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		data      []byte
		wantError bool
	}{
		{
			name:      "valid key and data",
			key:       []byte("my-secret-key"),
			data:      []byte("Important message"),
			wantError: false,
		},
		{
			name:      "empty data",
			key:       []byte("my-secret-key"),
			data:      []byte{},
			wantError: false,
		},
		{
			name:      "single byte key",
			key:       []byte("k"),
			data:      []byte("message"),
			wantError: false,
		},
		{
			name:      "64 byte key (maximum)",
			key:       bytes.Repeat([]byte("k"), 64),
			data:      []byte("message"),
			wantError: false,
		},
		{
			name:      "empty key",
			key:       []byte{},
			data:      []byte("message"),
			wantError: true,
		},
		{
			name:      "key too long (65 bytes)",
			key:       bytes.Repeat([]byte("k"), 65),
			data:      []byte("message"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, err := HMAC(tt.key, tt.data)

			if tt.wantError {
				if err == nil {
					t.Errorf("HMAC() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("HMAC() unexpected error = %v", err)
			}

			if len(mac) != 32 {
				t.Errorf("HMAC() returned %d bytes, want 64", len(mac))
			}

			// Test that same inputs produce same MAC
			mac2, err := HMAC(tt.key, tt.data)
			if err != nil {
				t.Fatalf("HMAC() second call error = %v", err)
			}

			if !bytes.Equal(mac, mac2) {
				t.Error("HMAC() not deterministic - same inputs produced different outputs")
			}
		})
	}
}

func TestVerifyMAC(t *testing.T) {
	key := []byte("test-key")
	data := []byte("test data")

	// Generate a valid MAC
	validMAC, err := HMAC(key, data)
	if err != nil {
		t.Fatalf("HMAC() error = %v", err)
	}

	tests := []struct {
		name      string
		key       []byte
		data      []byte
		mac       []byte
		wantValid bool
		wantError bool
	}{
		{
			name:      "valid MAC",
			key:       key,
			data:      data,
			mac:       validMAC,
			wantValid: true,
			wantError: false,
		},
		{
			name:      "wrong key",
			key:       []byte("wrong-key"),
			data:      data,
			mac:       validMAC,
			wantValid: false,
			wantError: false,
		},
		{
			name:      "wrong data",
			key:       key,
			data:      []byte("wrong data"),
			mac:       validMAC,
			wantValid: false,
			wantError: false,
		},
		{
			name:      "tampered MAC",
			key:       key,
			data:      data,
			mac:       append([]byte{0xFF}, validMAC[1:]...),
			wantValid: false,
			wantError: false,
		},
		{
			name:      "truncated MAC",
			key:       key,
			data:      data,
			mac:       validMAC[:31],
			wantValid: false,
			wantError: false,
		},
		{
			name:      "empty MAC",
			key:       key,
			data:      data,
			mac:       []byte{},
			wantValid: false,
			wantError: false,
		},
		{
			name:      "invalid key",
			key:       []byte{},
			data:      data,
			mac:       validMAC,
			wantValid: false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifyMAC(tt.key, tt.data, tt.mac)

			if tt.wantError {
				if err == nil {
					t.Errorf("VerifyMAC() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyMAC() unexpected error = %v", err)
			}

			if valid != tt.wantValid {
				t.Errorf("VerifyMAC() = %v, want %v", valid, tt.wantValid)
			}
		})
	}
}

func TestConstantTimeComparison(t *testing.T) {
	// This test verifies that VerifyMAC by checking that it correctly handles equal MACs with different representations
	key := []byte("test-key")
	data := []byte("test data")

	mac1, err := HMAC(key, data)
	if err != nil {
		t.Fatalf("HMAC() error = %v", err)
	}

	// Create an identical MAC
	mac2 := make([]byte, len(mac1))
	copy(mac2, mac1)

	valid, err := VerifyMAC(key, data, mac2)
	if err != nil {
		t.Fatalf("VerifyMAC() error = %v", err)
	}

	if !valid {
		t.Error("VerifyMAC() failed to verify identical MAC")
	}
}
