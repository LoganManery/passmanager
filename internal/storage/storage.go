package storage

import "github.com/loganmanery/passmanager/pkg/models"

// StorageService defines the interface for database operations
type StorageService interface {
	// Initialize initializes the storage service
	Initialize() error

	// Close closes the storage connection
	Close() error

	// GetSalt retrieves the salt from the database or creates a new one
	GetSalt() ([]byte, error)

	// SaveSalt saves a salt to the database
	SaveSalt(salt []byte) error

	// GetTestVector retrieves the test vector for master password verification
	GetTestVector() ([]byte, error)

	// SaveTestVector saves a test vector to the database
	SaveTestVector(vector []byte) error

	// AddPassword adds a new password entry
	AddPassword(entry *models.PasswordEntry, encPassword, encNotes []byte) (int64, error)

	// GetPassword retrieves a password entry by ID
	GetPassword(id int64) (*models.PasswordEntry, []byte, []byte, error)

	// GetAllPasswords retrieves all password entries (without sensitive data)
	GetAllPasswords() ([]models.PasswordEntry, error)

	// UpdatePassword updates an existing password entry
	UpdatePassword(entry *models.PasswordEntry, encPassword, encNotes []byte) error

	// DeletePassword deletes a password entry
	DeletePassword(id int64) error

	// SearchPasswords searches for password entries
	SearchPasswords(params models.SearchParams) ([]models.PasswordEntry, error)

	// ExportData exports all entries for backup
	ExportData() ([]map[string]interface{}, error)

	// ImportData imports entries from a backup
	ImportData(entries []map[string]interface{}) error
}

// NewStorageService creates a new instance of the default storage service
func NewStorageService(dbPath string) StorageService {
	return newSQLiteStorage(dbPath)
}
