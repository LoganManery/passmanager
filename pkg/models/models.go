package models

import "time"

// PasswordEntry represents a stored password entry
type PasswordEntry struct {
	ID          int64
	Title       string
	URL         string
	Username    string
	Password    string
	Notes       string
	Category    string
	CreatedAt   time.Time
	LastUpdated time.Time
}

// SearchParams represents search criteria for password entries
type SearchParams struct {
	Keyword  string
	Category string
	SortBy   string
	SortDesc bool
	Limit    int
	Offset   int
}
