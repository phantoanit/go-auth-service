package service

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// argon2Params holds Argon2id parameters extracted from PHC string
type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
}

// parseArgon2idHash parses PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func (s *AuthService) parseArgon2idHash(encodedHash string) (*argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")

	// Expected format: ["", "argon2id", "v=19", "m=65536,t=3,p=4", "salt", "hash"]
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("invalid algorithm: expected argon2id, got %s", parts[1])
	}

	// Parse version (v=19)
	if parts[2] != "v=19" {
		return nil, nil, nil, fmt.Errorf("unsupported version: %s", parts[2])
	}

	// Parse parameters: m=65536,t=3,p=4
	params := &argon2Params{
		keyLen: 32, // Default 256-bit
	}

	paramParts := strings.Split(parts[3], ",")
	for _, param := range paramParts {
		kv := strings.Split(param, "=")
		if len(kv) != 2 {
			continue
		}

		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid parameter %s: %w", kv[0], err)
		}

		switch kv[0] {
		case "m":
			params.memory = uint32(value)
		case "t":
			params.time = uint32(value)
		case "p":
			params.threads = uint8(value)
		}
	}

	// Decode salt (base64)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Decode hash (base64)
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	params.keyLen = uint32(len(hash))

	return params, salt, hash, nil
}

// subtleCompare performs constant-time comparison to prevent timing attacks
func subtleCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
