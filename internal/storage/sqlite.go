package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/loganmanery/passmanager/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStorage implements StorageService using SQLite
type SQLiteStorage struct {
	db     *sql.DB
	dbPath string
}

// newSQLiteStorage creates a new SQLite storage service
func newSQLiteStorage(dbPath string) *SQLiteStorage {
	return &SQLiteStorage{
		dbPath: dbPath,
	}
}

// Initialize initializes the database connection and tables
func (s *SQLiteStorage) Initialize() error {
	// Open SQLite database
	db, err := sql.Open("sqlite3", s.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	s.db = db

	// Initialize the database schema
	return s.initializeSchema()
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetSalt retrieves the salt from the database
func (s *SQLiteStorage) GetSalt() ([]byte, error) {
	var salt []byte
	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'salt'").Scan(&salt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("no salt found, please create a master password first")
		}
		return nil, err
	}
	return salt, nil
}

// SaveSalt saves a salt to the database
func (s *SQLiteStorage) SaveSalt(salt []byte) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "salt", salt)
	return err
}

// GetTestVector retrieves the test vector for master password verification
func (s *SQLiteStorage) GetTestVector() ([]byte, error) {
	var testVector []byte
	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'test_vector'").Scan(&testVector)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No test vector yet, not an error
		}
		return nil, err
	}
	return testVector, nil
}

// SaveTestVector saves a test vector to the database
func (s *SQLiteStorage) SaveTestVector(vector []byte) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "test_vector", vector)
	return err
}

// AddPassword adds a new password entry
func (s *SQLiteStorage) AddPassword(entry *models.PasswordEntry, encPassword, encNotes []byte) (int64, error) {
	// Insert the entry
	result, err := s.db.Exec(`
		INSERT INTO passwords (title, url, username, password, notes, category, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, entry.Title, entry.URL, entry.Username, encPassword, encNotes, entry.Category)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetPassword retrieves a password entry by ID
func (s *SQLiteStorage) GetPassword(id int64) (*models.PasswordEntry, []byte, []byte, error) {
	var entry models.PasswordEntry
	var encPassword, encNotes []byte
	var createdAt, updatedAt string

	err := s.db.QueryRow(`
		SELECT id, title, url, username, password, notes, category, created_at, updated_at
		FROM passwords WHERE id = ?
	`, id).Scan(&entry.ID, &entry.Title, &entry.URL, &entry.Username, &encPassword, &encNotes, &entry.Category, &createdAt, &updatedAt)
	if err != nil {
		return nil, nil, nil, err
	}

	// Parse timestamps
	entry.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	entry.LastUpdated, _ = time.Parse(time.RFC3339, updatedAt)

	return &entry, encPassword, encNotes, nil

}

// GetAllPasswords retrieves all password entries (without sensitive data)
func (s *SQLiteStorage) GetAllPasswords() ([]models.PasswordEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, title, url, username, category, created_at, updated_at
		FROM passwords ORDER BY title
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.PasswordEntry
	for rows.Next() {
		var entry models.PasswordEntry
		var createdAt, updatedAt string
		err := rows.Scan(&entry.ID, &entry.Title, &entry.URL, &entry.Username,
			&entry.Category, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		// Parse timestamps
		entry.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		entry.LastUpdated, _ = time.Parse(time.RFC3339, updatedAt)

		// Note: Password and Notes are not loaded here for security
		entries = append(entries, entry)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// UpdatePassword updates an existing password entry
func (s *SQLiteStorage) UpdatePassword(entry *models.PasswordEntry, encPassword, encNotes []byte) error {
	// Update the entry
	_, err := s.db.Exec(`
		UPDATE passwords
		SET title = ?, url = ?, username = ?, password = ?, notes = ?, category = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, entry.Title, entry.URL, entry.Username, encPassword, encNotes, entry.Category, entry.ID)

	return err
}

// DeletePassword deletes a password entry
func (s *SQLiteStorage) DeletePassword(id int64) error {
	_, err := s.db.Exec("DELETE FROM passwords WHERE id = ?", id)
	return err
}

// SearchPasswords searches for password entries
func (s *SQLiteStorage) SearchPasswords(params models.SearchParams) ([]models.PasswordEntry, error) {
	// Base query
	query := `
		SELECT id, title, url, username, category, created_at, updated_at
		FROM passwords
		WHERE 1=1
	`
	var args []interface{}

	// Add search conditions
	if params.Keyword != "" {
		searchTerm := "%" + params.Keyword + "%"
		query += ` AND (title LIKE ? OR url LIKE ? OR username LIKE ?)`
		args = append(args, searchTerm, searchTerm, searchTerm)
	}

	if params.Category != "" {
		query += ` AND category = ?`
		args = append(args, params.Category)
	}

	// Add sorting
	if params.SortBy != "" {
		query += ` ORDER BY ` + params.SortBy
		if params.SortDesc {
			query += ` DESC`
		} else {
			query += ` ASC`
		}
	} else {
		query += ` ORDER BY title ASC`
	}

	// Add pagination
	if params.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, params.Limit)

		if params.Offset > 0 {
			query += ` OFFSET ?`
			args = append(args, params.Offset)
		}
	}

	// Execute query
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.PasswordEntry
	for rows.Next() {
		var entry models.PasswordEntry
		var createdAt, updatedAt string
		err := rows.Scan(&entry.ID, &entry.Title, &entry.URL, &entry.Username,
			&entry.Category, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		// Parse timestamps
		entry.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		entry.LastUpdated, _ = time.Parse(time.RFC3339, updatedAt)

		entries = append(entries, entry)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// ExportData exports all entries for backup
func (s *SQLiteStorage) ExportData() ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`
		SELECT id, title, url, username, password, notes, category, created_at, updated_at
		FROM passwords
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id int64
		var title, url, username, category, createdAt, updatedAt string
		var password, notes []byte

		err := rows.Scan(&id, &title, &url, &username, &password, &notes,
			&category, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		entry := map[string]interface{}{
			"id":         id,
			"title":      title,
			"url":        url,
			"username":   username,
			"password":   password,
			"notes":      notes,
			"category":   category,
			"created_at": createdAt,
			"updated_at": updatedAt,
		}

		result = append(result, entry)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// ImportData imports entries from a backup
func (s *SQLiteStorage) ImportData(entries []map[string]interface{}) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO passwords (title, url, username, password, notes, category, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, entry := range entries {
		_, err = stmt.Exec(
			entry["title"],
			entry["url"],
			entry["username"],
			entry["password"],
			entry["notes"],
			entry["category"],
			entry["created_at"],
			entry["updated_at"],
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
