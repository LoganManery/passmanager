package crypto

import (
	"golang.org/x/crypto/argon2"
)

// Argon2 parameters
const (
	argonTime    = 3         // Number of iterations
	argonMemory  = 64 * 1024 // Memory in KiB (64 MB)
	argonThreads = 4         // Number of threads
	argonKeyLen  = 32        // Output key length (for AES-256)
)

// DeriveKey derives an encryption key from a password and salt using Argon2id
func (s *aesCryptoService) DeriveKey(password string, salt []byte) ([]byte, error) {
	// Generate the encryption key from master password
	key := argon2.IDKey(
		[]byte(password),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)

	return key, nil
}
