package crypto

// CryptoService defines the interface for encryption operations
type CryptoService interface {
	// DeriveKey derives an encryption key from a password and salt
	DeriveKey(password string, salt []byte) ([]byte, error)

	// GenerateSalt generates a cryptographically secure random salt
	GenerateSalt() ([]byte, error)

	// Encrypt encrypts plaintext using the provided key
	Encrypt(plaintext string, key []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the provided key
	Decrypt(ciphertext []byte, key []byte) (string, error)

	// VerifyKey verifies if a key can decrypt a test vector
	VerifyKey(key []byte, testVector []byte) (bool, error)
}

// NewCryptoService creates a new instance of the default crypto service
func NewCryptoService() CryptoService {
	return &aesCryptoService{}
}
