package manager

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/loganmanery/passmanager/internal/crypto"
	"github.com/loganmanery/passmanager/internal/models"
	"github.com/loganmanery/passmanager/internal/storage"
	"github.com/loganmanery/passmanager/pkg/generator"
)

// PasswordManager handles all password management operations
type PasswordManager struct {
	storage      storage.StorageService
	crypto       crypto.CryptoService
	masterKey    []byte
	initialized  bool
	lastActivity time.Time
}

// NewPasswordManager creates a new password manager instance
func NewPasswordManager(storagePath string) *PasswordManager {
	return &PasswordManager{
		storage:      storage.NewStorageService(storagePath),
		crypto:       crypto.NewCryptoService(),
		initialized:  false,
		lastActivity: time.Now(),
	}
}

// Initialize sets up the password manager and opens the database
func (pm *PasswordManager) Initialize() error {
	err := pm.storage.Initialize()
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	return nil
}

// CreateMasterPassword sets up a new master password and salt
func (pm *PasswordManager) CreateMasterPassword(masterPassword string) error {
	// Generate a random salt
	salt, err := pm.crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Save the salt
	err = pm.storage.SaveSalt(salt)
	if err != nil {
		return fmt.Errorf("failed to save salt: %w", err)
	}

	// Derive the master key
	pm.masterKey, err = pm.crypto.DeriveKey(masterPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create and save test vector for verification
	testData := "This is a test string to verify the master password."
	encryptedTest, err := pm.crypto.Encrypt(testData, pm.masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt test vector: %w", err)
	}

	err = pm.storage.SaveTestVector(encryptedTest)
	if err != nil {
		return fmt.Errorf("failed to save test vector: %w", err)
	}

	pm.initialized = true
	pm.updateLastActivity()
	return nil
}

// UnlockVault authenticates with the master password and unlocks the vault
func (pm *PasswordManager) UnlockVault(masterPassword string) error {
	// Get the salt
	salt, err := pm.storage.GetSalt()
	if err != nil {
		return fmt.Errorf("failed to get salt: %w", err)
	}

	// Derive the master key
	key, err := pm.crypto.DeriveKey(masterPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Verify the key with the test vector
	testVector, err := pm.storage.GetTestVector()
	if err != nil {
		return fmt.Errorf("failed to get test vector: %w", err)
	}

	correct, err := pm.crypto.VerifyKey(key, testVector)
	if err != nil {
		return fmt.Errorf("error verifying key: %w", err)
	}
	if !correct {
		return errors.New("invalid master password")
	}

	// Save the master key
	pm.masterKey = key
	pm.initialized = true
	pm.updateLastActivity()
	return nil
}

// IsLocked checks if the vault is locked
func (pm *PasswordManager) IsLocked() bool {
	return !pm.initialized
}

// Lock locks the vault
func (pm *PasswordManager) Lock() {
	pm.masterKey = nil
	pm.initialized = false
}

// AddPassword adds a new password entry
func (pm *PasswordManager) AddPassword(entry models.PasswordEntry) (int64, error) {
	if !pm.initialized {
		return 0, errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	// Encrypt sensitive fields
	encPassword, err := pm.crypto.Encrypt(entry.Password, pm.masterKey)
	if err != nil {
		return 0, err
	}

	var encNotes []byte
	if entry.Notes != "" {
		encNotes, err = pm.crypto.Encrypt(entry.Notes, pm.masterKey)
		if err != nil {
			return 0, err
		}
	}

	// Add to storage
	id, err := pm.storage.AddPassword(&entry, encPassword, encNotes)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// GetPassword retrieves a password entry by ID
func (pm *PasswordManager) GetPassword(id int64) (models.PasswordEntry, error) {
	if !pm.initialized {
		return models.PasswordEntry{}, errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	// Get from storage
	entry, encPassword, encNotes, err := pm.storage.GetPassword(id)
	if err != nil {
		return models.PasswordEntry{}, err
	}

	// Decrypt password
	password, err := pm.crypto.Decrypt(encPassword, pm.masterKey)
	if err != nil {
		return models.PasswordEntry{}, err
	}
	entry.Password = password

	// Decrypt notes if they exist
	if encNotes != nil && len(encNotes) > 0 {
		notes, err := pm.crypto.Decrypt(encNotes, pm.masterKey)
		if err != nil {
			return models.PasswordEntry{}, err
		}
		entry.Notes = notes
	}

	return *entry, nil
}

// GetAllPasswords retrieves all password entries (without sensitive data)
func (pm *PasswordManager) GetAllPasswords() ([]models.PasswordEntry, error) {
	if !pm.initialized {
		return nil, errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	return pm.storage.GetAllPasswords()
}

// UpdatePassword updates an existing password entry
func (pm *PasswordManager) UpdatePassword(entry models.PasswordEntry) error {
	if !pm.initialized {
		return errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	// Encrypt sensitive fields
	encPassword, err := pm.crypto.Encrypt(entry.Password, pm.masterKey)
	if err != nil {
		return err
	}

	var encNotes []byte
	if entry.Notes != "" {
		encNotes, err = pm.crypto.Encrypt(entry.Notes, pm.masterKey)
		if err != nil {
			return err
		}
	}

	// Update in storage
	return pm.storage.UpdatePassword(&entry, encPassword, encNotes)
}

// DeletePassword deletes a password entry
func (pm *PasswordManager) DeletePassword(id int64) error {
	if !pm.initialized {
		return errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	return pm.storage.DeletePassword(id)
}

// SearchPasswords searches for password entries
func (pm *PasswordManager) SearchPasswords(params models.SearchParams) ([]models.PasswordEntry, error) {
	if !pm.initialized {
		return nil, errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	return pm.storage.SearchPasswords(params)
}

// GeneratePassword creates a secure random password
func (pm *PasswordManager) GeneratePassword(options generator.PasswordOptions) (string, error) {
	pm.updateLastActivity()
	return generator.GeneratePassword(options)
}

// ExportVault exports the password vault to a file
func (pm *PasswordManager) ExportVault(filename string) error {
	if !pm.initialized {
		return errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	// Get all entries
	entries, err := pm.storage.ExportData()
	if err != nil {
		return err
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	// Encrypt the entire export
	encData, err := pm.crypto.Encrypt(string(jsonData), pm.masterKey)
	if err != nil {
		return err
	}

	// Base64 encode for safety
	encodedData := base64.StdEncoding.EncodeToString(encData)

	// Write to file
	return os.WriteFile(filename, []byte(encodedData), 0600)
}

// ImportVault imports the password vault from a file
func (pm *PasswordManager) ImportVault(filename string) error {
	if !pm.initialized {
		return errors.New("password manager not initialized")
	}
	pm.updateLastActivity()

	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Decode base64
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	// Decrypt
	jsonData, err := pm.crypto.Decrypt(decodedData, pm.masterKey)
	if err != nil {
		return err
	}

	// Parse JSON
	var entries []map[string]interface{}
	err = json.Unmarshal([]byte(jsonData), &entries)
	if err != nil {
		return err
	}

	// Import into storage
	return pm.storage.ImportData(entries)
}

// Close closes the password manager and its resources
func (pm *PasswordManager) Close() error {
	pm.Lock()
	return pm.storage.Close()
}

// updateLastActivity updates the last activity timestamp
func (pm *PasswordManager) updateLastActivity() {
	pm.lastActivity = time.Now()
}

// GetLastActivity returns the last activity timestamp
func (pm *PasswordManager) GetLastActivity() time.Time {
	return pm.lastActivity
}
