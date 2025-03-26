package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/loganmanery/passmanager/pkg/generator"
	"github.com/loganmanery/passmanager/pkg/manager"
	"github.com/loganmanery/passmanager/pkg/models"

	"golang.org/x/term"
)

const (
	dbFileName = "password_vault.db"
)

func main() {
	// Get home directory for storing the database
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	// Create .passmanager directory if it doesn't exist
	configDir := filepath.Join(homeDir, ".passmanager")
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		fmt.Printf("Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	// Database path
	dbPath := filepath.Join(configDir, dbFileName)

	// Create password manager
	pm := manager.NewPasswordManager(dbPath)
	defer pm.Close()

	// Initialize
	err = pm.Initialize()
	if err != nil {
		fmt.Printf("Error initializing password manager: %v\n", err)
		os.Exit(1)
	}

	// Run the CLI
	runCLI(pm)
}

// runCLI runs the command-line interface
func runCLI(pm *manager.PasswordManager) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== Password Manager ===")

	// First, unlock or create master password
	err := unlockVault(pm, reader)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Main menu
	for {
		fmt.Println("\nMain Menu:")
		fmt.Println("1. List all passwords")
		fmt.Println("2. Add new password")
		fmt.Println("3. View password details")
		fmt.Println("4. Update password")
		fmt.Println("5. Delete password")
		fmt.Println("6. Generate password")
		fmt.Println("7. Export vault")
		fmt.Println("8. Import vault")
		fmt.Println("9. Lock vault")
		fmt.Println("0. Exit")
		fmt.Print("Enter your choice: ")

		choice, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			listPasswords(pm)
		case "2":
			addPassword(pm, reader)
		case "3":
			viewPassword(pm, reader)
		case "4":
			updatePassword(pm, reader)
		case "5":
			deletePassword(pm, reader)
		case "6":
			generatePassword(pm, reader)
		case "7":
			exportVault(pm, reader)
		case "8":
			importVault(pm, reader)
		case "9":
			pm.Lock()
			fmt.Println("Vault locked.")
			err := unlockVault(pm, reader)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
		case "0":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid choice, please try again.")
		}
	}
}

// unlockVault handles vault unlocking or creation
func unlockVault(pm *manager.PasswordManager, reader *bufio.Reader) error {
	// Check if we need to create a master password
	_ = pm.GetLastActivity() // Just get the timestamp, we don't actually use it
	if pm.IsLocked() {
		// Try to unlock first
		fmt.Print("Enter master password: ")
		password, err := readPassword()
		if err != nil {
			return err
		}

		err = pm.UnlockVault(password)
		if err != nil {
			// If it fails, we might need to create a new master password
			if strings.Contains(err.Error(), "no salt found") {
				fmt.Println("No vault found. Let's create a new one.")
				return createMasterPassword(pm, reader)
			}
			return err
		}

		fmt.Println("Vault unlocked successfully!")
		return nil
	}

	return nil
}

// createMasterPassword handles creation of a new master password
func createMasterPassword(pm *manager.PasswordManager, reader *bufio.Reader) error {
	var password, confirm string
	var err error

	for {
		fmt.Print("Create a new master password: ")
		password, err = readPassword()
		if err != nil {
			return err
		}

		if len(password) < 8 {
			fmt.Println("Password must be at least 8 characters long.")
			continue
		}

		fmt.Print("Confirm master password: ")
		confirm, err = readPassword()
		if err != nil {
			return err
		}

		if password != confirm {
			fmt.Println("Passwords do not match. Please try again.")
			continue
		}

		break
	}

	err = pm.CreateMasterPassword(password)
	if err != nil {
		return err
	}

	fmt.Println("Master password created successfully!")
	return nil
}

// readPassword reads a password without echoing it to the terminal
func readPassword() (string, error) {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add a newline after password input
	if err != nil {
		return "", err
	}

	return string(bytePassword), nil
}

// listPasswords displays all stored passwords
func listPasswords(pm *manager.PasswordManager) {
	entries, err := pm.GetAllPasswords()
	if err != nil {
		fmt.Printf("Error listing passwords: %v\n", err)
		return
	}

	if len(entries) == 0 {
		fmt.Println("No passwords found.")
		return
	}

	fmt.Println("\nStored Passwords:")
	fmt.Println("ID   | Title                 | Username               | Category")
	fmt.Println("-----+-----------------------+------------------------+----------")

	for _, entry := range entries {
		title := truncateString(entry.Title, 20)
		username := truncateString(entry.Username, 22)
		category := truncateString(entry.Category, 10)

		fmt.Printf("%-4d | %-21s | %-22s | %s\n",
			entry.ID, title, username, category)
	}
}

// addPassword adds a new password entry
func addPassword(pm *manager.PasswordManager, reader *bufio.Reader) {
	var entry models.PasswordEntry

	fmt.Print("Title: ")
	entry.Title = readLine(reader)

	fmt.Print("URL: ")
	entry.URL = readLine(reader)

	fmt.Print("Username: ")
	entry.Username = readLine(reader)

	fmt.Print("Password (leave empty to generate): ")
	entry.Password = readLine(reader)

	if entry.Password == "" {
		// Generate a password
		genOptions := generator.DefaultOptions()
		password, err := pm.GeneratePassword(genOptions)
		if err != nil {
			fmt.Printf("Error generating password: %v\n", err)
			return
		}
		entry.Password = password
		fmt.Printf("Generated password: %s\n", password)
	}

	fmt.Print("Notes: ")
	entry.Notes = readLine(reader)

	fmt.Print("Category: ")
	entry.Category = readLine(reader)

	id, err := pm.AddPassword(entry)
	if err != nil {
		fmt.Printf("Error adding password: %v\n", err)
		return
	}

	fmt.Printf("Password added with ID: %d\n", id)
}

// viewPassword displays a single password entry
func viewPassword(pm *manager.PasswordManager, reader *bufio.Reader) {
	fmt.Print("Enter password ID: ")
	idStr := readLine(reader)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Println("Invalid ID.")
		return
	}

	entry, err := pm.GetPassword(id)
	if err != nil {
		fmt.Printf("Error retrieving password: %v\n", err)
		return
	}

	fmt.Println("\nPassword Details:")
	fmt.Printf("Title: %s\n", entry.Title)
	fmt.Printf("URL: %s\n", entry.URL)
	fmt.Printf("Username: %s\n", entry.Username)
	fmt.Printf("Password: %s\n", entry.Password)
	fmt.Printf("Notes: %s\n", entry.Notes)
	fmt.Printf("Category: %s\n", entry.Category)
	fmt.Printf("Last Updated: %s\n", entry.LastUpdated.Format("2006-01-02 15:04:05"))
}

// updatePassword updates an existing password entry
func updatePassword(pm *manager.PasswordManager, reader *bufio.Reader) {
	fmt.Print("Enter password ID to update: ")
	idStr := readLine(reader)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Println("Invalid ID.")
		return
	}

	// Get the current entry
	entry, err := pm.GetPassword(id)
	if err != nil {
		fmt.Printf("Error retrieving password: %v\n", err)
		return
	}

	// Show current values and prompt for new ones
	fmt.Printf("Title [%s]: ", entry.Title)
	newTitle := readLine(reader)
	if newTitle != "" {
		entry.Title = newTitle
	}

	fmt.Printf("URL [%s]: ", entry.URL)
	newURL := readLine(reader)
	if newURL != "" {
		entry.URL = newURL
	}

	fmt.Printf("Username [%s]: ", entry.Username)
	newUsername := readLine(reader)
	if newUsername != "" {
		entry.Username = newUsername
	}

	fmt.Print("Password (leave empty to keep current, or type 'generate' for new): ")
	newPassword := readLine(reader)
	if newPassword == "generate" {
		genOptions := generator.DefaultOptions()
		password, err := pm.GeneratePassword(genOptions)
		if err != nil {
			fmt.Printf("Error generating password: %v\n", err)
			return
		}
		entry.Password = password
		fmt.Printf("Generated password: %s\n", password)
	} else if newPassword != "" {
		entry.Password = newPassword
	}

	fmt.Printf("Notes [%s]: ", entry.Notes)
	newNotes := readLine(reader)
	if newNotes != "" {
		entry.Notes = newNotes
	}

	fmt.Printf("Category [%s]: ", entry.Category)
	newCategory := readLine(reader)
	if newCategory != "" {
		entry.Category = newCategory
	}

	err = pm.UpdatePassword(entry)
	if err != nil {
		fmt.Printf("Error updating password: %v\n", err)
		return
	}

	fmt.Println("Password updated successfully.")
}

// deletePassword deletes a password entry
func deletePassword(pm *manager.PasswordManager, reader *bufio.Reader) {
	fmt.Print("Enter password ID to delete: ")
	idStr := readLine(reader)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		fmt.Println("Invalid ID.")
		return
	}

	fmt.Print("Are you sure you want to delete this password? (y/n): ")
	confirm := readLine(reader)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("Deletion cancelled.")
		return
	}

	err = pm.DeletePassword(id)
	if err != nil {
		fmt.Printf("Error deleting password: %v\n", err)
		return
	}

	fmt.Println("Password deleted successfully.")
}

// generatePassword generates a random password
func generatePassword(pm *manager.PasswordManager, reader *bufio.Reader) {
	options := generator.DefaultOptions()

	fmt.Printf("Password length [%d]: ", options.Length)
	lengthStr := readLine(reader)
	if lengthStr != "" {
		length, err := strconv.Atoi(lengthStr)
		if err == nil && length > 0 {
			options.Length = length
		}
	}

	// Format options yes/no based on boolean
	getLowercase := "y"
	if !options.IncludeLowercase {
		getLowercase = "n"
	}
	fmt.Printf("Include lowercase letters? (y/n) [%s]: ", getLowercase)
	options.IncludeLowercase = confirmOption(readLine(reader), options.IncludeLowercase)

	getUppercase := "y"
	if !options.IncludeUppercase {
		getUppercase = "n"
	}
	fmt.Printf("Include uppercase letters? (y/n) [%s]: ", getUppercase)
	options.IncludeUppercase = confirmOption(readLine(reader), options.IncludeUppercase)

	getNumbers := "y"
	if !options.IncludeNumbers {
		getNumbers = "n"
	}
	fmt.Printf("Include numbers? (y/n) [%s]: ", getNumbers)
	options.IncludeNumbers = confirmOption(readLine(reader), options.IncludeNumbers)

	getSymbols := "y"
	if !options.IncludeSymbols {
		getSymbols = "n"
	}
	fmt.Printf("Include symbols? (y/n) [%s]: ", getSymbols)
	options.IncludeSymbols = confirmOption(readLine(reader), options.IncludeSymbols)

	getSimilar := "y"
	if !options.ExcludeSimilar {
		getSimilar = "n"
	}
	fmt.Printf("Exclude similar characters (i, l, 1, L, o, 0, O)? (y/n) [%s]: ", getSimilar)
	options.ExcludeSimilar = confirmOption(readLine(reader), options.ExcludeSimilar)

	password, err := pm.GeneratePassword(options)
	if err != nil {
		fmt.Printf("Error generating password: %v\n", err)
		return
	}

	fmt.Printf("\nGenerated Password: %s\n", password)
}

// exportVault exports the password vault to a file
func exportVault(pm *manager.PasswordManager, reader *bufio.Reader) {
	fmt.Print("Enter export file path: ")
	filePath := readLine(reader)
	if filePath == "" {
		fmt.Println("Export cancelled.")
		return
	}

	err := pm.ExportVault(filePath)
	if err != nil {
		fmt.Printf("Error exporting vault: %v\n", err)
		return
	}

	fmt.Println("Vault exported successfully.")
}

// importVault imports the password vault from a file
func importVault(pm *manager.PasswordManager, reader *bufio.Reader) {
	fmt.Print("Enter import file path: ")
	filePath := readLine(reader)
	if filePath == "" {
		fmt.Println("Import cancelled.")
		return
	}

	fmt.Print("This will overwrite any existing passwords. Continue? (y/n): ")
	confirm := readLine(reader)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("Import cancelled.")
		return
	}

	err := pm.ImportVault(filePath)
	if err != nil {
		fmt.Printf("Error importing vault: %v\n", err)
		return
	}

	fmt.Println("Vault imported successfully.")
}

// Helper functions

// readLine reads a line from the reader and trims spaces
func readLine(reader *bufio.Reader) string {
	text, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(text)
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// confirmOption handles y/n confirmation for options
func confirmOption(input string, defaultValue bool) bool {
	input = strings.ToLower(input)
	if input == "" {
		return defaultValue
	}
	return input == "y" || input == "yes"
}
