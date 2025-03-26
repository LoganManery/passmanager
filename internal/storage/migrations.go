package storage

// initializeSchema sets up the necessary database tables
func (s *SQLiteStorage) initializeSchema() error {
	// Create config table
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value BLOB
		)
	`)
	if err != nil {
		return err
	}

	// Create passwords table
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS passwords (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			url TEXT,
			username TEXT,
			password BLOB,
			notes BLOB,
			category TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create categories table
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS categories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			color TEXT,
			icon TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create audit log table
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id INTEGER,
			details TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create indexes
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_passwords_title ON passwords(title)`)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_passwords_category ON passwords(category)`)
	if err != nil {
		return err
	}

	return nil
}
