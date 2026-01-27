package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

// HashPassword generates an Argon2id hash for the given password
func HashPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Argon2id parameters (matching production settings)
	const (
		time    = 3
		memory  = 64 * 1024 // 64 MB
		threads = 4
		keyLen  = 32
	)

	// Generate the hash
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	// Encode in PHC string format
	// $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads, encodedSalt, encodedHash,
	), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run hash_password.go <password>")
		fmt.Println("Example: go run hash_password.go Vhv@2026")
		os.Exit(1)
	}

	password := os.Args[1]
	hash, err := HashPassword(password)
	if err != nil {
		fmt.Printf("Error generating hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Argon2id Hash:\n%s\n", hash)
	fmt.Println("\nCopy the hash above and replace in migration file:")
	fmt.Println("migrations/000006_seed_initial_data.up.sql")
}
