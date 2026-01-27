package service

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestArgon2idPasswordHashing(t *testing.T) {
	// Create a minimal auth service for testing
	service := &AuthService{}

	t.Run("Hash and Verify Password Success", func(t *testing.T) {
		password := "MySecureP@ssw0rd123!"

		// Hash password
		hashedPassword, err := service.hashPassword(password)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}

		t.Logf("Hashed password: %s", hashedPassword)

		// Verify correct password
		if !service.verifyPassword(password, hashedPassword) {
			t.Error("Failed to verify correct password")
		}
	})

	t.Run("Verify Wrong Password Fails", func(t *testing.T) {
		password := "CorrectPassword123"
		wrongPassword := "WrongPassword456"

		hashedPassword, err := service.hashPassword(password)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}

		// Verify wrong password should fail
		if service.verifyPassword(wrongPassword, hashedPassword) {
			t.Error("Wrong password was incorrectly verified")
		}
	})

	t.Run("PHC Format Validation", func(t *testing.T) {
		password := "TestPassword"

		hashedPassword, err := service.hashPassword(password)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}

		// Check PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
		if len(hashedPassword) < 50 {
			t.Error("Hashed password too short")
		}

		if hashedPassword[:10] != "$argon2id$" {
			t.Errorf("Invalid format prefix: %s", hashedPassword[:10])
		}
	})

	t.Run("Parse Valid Hash", func(t *testing.T) {
		// Create a known valid hash
		password := "test123"
		hashedPassword, _ := service.hashPassword(password)

		params, salt, hash, err := service.parseArgon2idHash(hashedPassword)
		if err != nil {
			t.Fatalf("Failed to parse hash: %v", err)
		}

		if params.memory != 64*1024 {
			t.Errorf("Wrong memory parameter: got %d, want %d", params.memory, 64*1024)
		}
		if params.time != 3 {
			t.Errorf("Wrong time parameter: got %d, want 3", params.time)
		}
		if params.threads != 4 {
			t.Errorf("Wrong threads parameter: got %d, want 4", params.threads)
		}
		if len(salt) != 16 {
			t.Errorf("Wrong salt length: got %d, want 16", len(salt))
		}
		if len(hash) != 32 {
			t.Errorf("Wrong hash length: got %d, want 32", len(hash))
		}
	})

	t.Run("Parse Invalid Hash Formats", func(t *testing.T) {
		testCases := []struct {
			name string
			hash string
		}{
			{"Empty", ""},
			{"No Delimiters", "argon2idhash"},
			{"Wrong Algorithm", "$bcrypt$10$salt$hash"},
			{"Missing Parts", "$argon2id$v=19$m=65536"},
			{"Invalid Base64", "$argon2id$v=19$m=65536,t=3,p=4$!!!invalid!!!$hash"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, _, err := service.parseArgon2idHash(tc.hash)
				if err == nil {
					t.Error("Expected error for invalid hash, got nil")
				}
			})
		}
	})

	t.Run("Different Passwords Produce Different Hashes", func(t *testing.T) {
		password1 := "password123"
		password2 := "password456"

		hash1, _ := service.hashPassword(password1)
		hash2, _ := service.hashPassword(password2)

		if hash1 == hash2 {
			t.Error("Same password produced identical hashes (salt not random)")
		}
	})

	t.Run("Same Password Produces Different Hashes (Salt Randomness)", func(t *testing.T) {
		password := "samepassword"

		hash1, _ := service.hashPassword(password)
		hash2, _ := service.hashPassword(password)

		if hash1 == hash2 {
			t.Error("Same password hashed twice produced identical hashes (salt not random)")
		}

		// But both should verify correctly
		if !service.verifyPassword(password, hash1) || !service.verifyPassword(password, hash2) {
			t.Error("Failed to verify correctly hashed passwords")
		}
	})

	t.Run("OWASP Parameters", func(t *testing.T) {
		// Verify we're using OWASP 2023 recommended parameters
		password := "test"
		hashedPassword, _ := service.hashPassword(password)

		params, _, _, err := service.parseArgon2idHash(hashedPassword)
		if err != nil {
			t.Fatalf("Failed to parse hash: %v", err)
		}

		// OWASP recommendations for Argon2id:
		// - Memory: 46 MB minimum (we use 64 MB for better security)
		// - Iterations: 1-3 (we use 3)
		// - Parallelism: 1-4 (we use 4)
		// - Salt: 128 bits minimum (we use 128 bits)
		// - Hash: 256 bits minimum (we use 256 bits)

		if params.memory < 46*1024 {
			t.Errorf("Memory parameter below OWASP minimum: %d KB", params.memory)
		}
		if params.time < 1 || params.time > 3 {
			t.Errorf("Time parameter outside OWASP range: %d", params.time)
		}
		if params.threads < 1 || params.threads > 4 {
			t.Errorf("Threads parameter outside OWASP range: %d", params.threads)
		}
	})

	t.Run("Timing Attack Resistance", func(t *testing.T) {
		// This is a basic test - real timing attack testing requires more sophisticated methods
		password := "correctpassword"
		hashedPassword, _ := service.hashPassword(password)

		// These should all take roughly the same time (constant-time comparison)
		testPasswords := []string{
			"wrongpassword",
			"correctpassword",
			"a",
			"verylongwrongpasswordthatshouldalsobeconstanttime",
		}

		for _, testPwd := range testPasswords {
			// Just verify it works - actual timing measurement would need benchmarks
			_ = service.verifyPassword(testPwd, hashedPassword)
		}
	})
}

func BenchmarkArgon2idHash(b *testing.B) {
	service := &AuthService{}
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.hashPassword(password)
	}
}

func BenchmarkArgon2idVerify(b *testing.B) {
	service := &AuthService{}
	password := "BenchmarkPassword123!"
	hashedPassword, _ := service.hashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = service.verifyPassword(password, hashedPassword)
	}
}

// TestArgon2idCompatibility tests compatibility with standard Argon2id implementations
func TestArgon2idCompatibility(t *testing.T) {
	service := &AuthService{}

	t.Run("Manual Hash Verification", func(t *testing.T) {
		// Create a hash manually using argon2 package
		password := "testpassword"
		salt := []byte("0123456789abcdef") // 16 bytes

		hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

		// Encode in PHC format
		saltB64 := base64.RawStdEncoding.EncodeToString(salt)
		hashB64 := base64.RawStdEncoding.EncodeToString(hash)
		phcHash := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", saltB64, hashB64)

		// Verify using our service
		if !service.verifyPassword(password, phcHash) {
			t.Error("Failed to verify manually created hash")
		}
	})
}
