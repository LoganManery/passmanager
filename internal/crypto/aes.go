package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// aesCryptoService implements CryptoService using AES-GCM
type aesCryptoService struct{}

// Encrypt encrypts a string using AES-GCM with the provided key
func (s *aesCryptoService) Encrypt(plaintext string, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}

// Decrypt decrypts a byte slice using AES-GCM with the provided key
func (s *aesCryptoService) Decrypt(ciphertext []byte, key []byte) (string, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Ensure the ciphertext is long enough
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Decrypt and verify the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GenerateSalt generates a cryptographically secure random salt
func (s *aesCryptoService) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

// VerifyKey verifies if a key can decrypt a test vector
func (s *aesCryptoService) VerifyKey(key []byte, testVector []byte) (bool, error) {
	_, err := s.Decrypt(testVector, key)
	return err == nil, nil
}
