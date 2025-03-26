package generator

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// PasswordOptions configures password generation
type PasswordOptions struct {
	Length           int
	IncludeLowercase bool
	IncludeUppercase bool
	IncludeNumbers   bool
	IncludeSymbols   bool
	ExcludeSimilar   bool
	ExcludeAmbiguous bool
}

// DefaultOptions returns sensible default password options
func DefaultOptions() PasswordOptions {
	return PasswordOptions{
		Length:           16,
		IncludeLowercase: true,
		IncludeUppercase: true,
		IncludeNumbers:   true,
		IncludeSymbols:   true,
		ExcludeSimilar:   true,
		ExcludeAmbiguous: false,
	}
}

// Character sets
const (
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers   = "0123456789"
	symbols   = "!@#$%^&*()-_=+[]{}|;:,./<>?~"
	similar   = "il1Lo0O"
	ambiguous = "`{}[]()|\\/'\"`~,;:.<>"
)

// GeneratePassword creates a random password according to options
func GeneratePassword(options PasswordOptions) (string, error) {
	if options.Length <= 0 {
		return "", errors.New("password length must be positive")
	}

	// Build character set
	var chars []rune

	if options.IncludeLowercase {
		for _, c := range lowercase {
			if options.ExcludeSimilar && containsRune(similar, c) {
				continue
			}
			chars = append(chars, c)
		}
	}

	if options.IncludeUppercase {
		for _, c := range uppercase {
			if options.ExcludeSimilar && containsRune(similar, c) {
				continue
			}
			chars = append(chars, c)
		}
	}

	if options.IncludeNumbers {
		for _, c := range numbers {
			if options.ExcludeSimilar && containsRune(similar, c) {
				continue
			}
			chars = append(chars, c)
		}
	}

	if options.IncludeSymbols {
		for _, c := range symbols {
			if options.ExcludeAmbiguous && containsRune(ambiguous, c) {
				continue
			}
			chars = append(chars, c)
		}
	}

	if len(chars) == 0 {
		return "", errors.New("no character set selected")
	}

	// Generate password
	result := make([]rune, options.Length)
	for i := 0; i < options.Length; i++ {
		idx, err := randomInt(len(chars))
		if err != nil {
			return "", err
		}
		result[i] = chars[idx]
	}

	// Ensure password meets all character class requirements
	if !meetsRequirements(string(result), options) {
		// Regenerate if requirements not met
		return GeneratePassword(options)
	}

	return string(result), nil
}

// meetsRequirements checks if a password meets all required character classes
func meetsRequirements(password string, options PasswordOptions) bool {
	hasLower := !options.IncludeLowercase
	hasUpper := !options.IncludeUppercase
	hasNumber := !options.IncludeNumbers
	hasSymbol := !options.IncludeSymbols

	for _, c := range password {
		if containsRune(lowercase, c) {
			hasLower = true
		} else if containsRune(uppercase, c) {
			hasUpper = true
		} else if containsRune(numbers, c) {
			hasNumber = true
		} else if containsRune(symbols, c) {
			hasSymbol = true
		}
	}

	return hasLower && hasUpper && hasNumber && hasSymbol
}

// randomInt generates a cryptographically secure random integer between 0 and max-1
func randomInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be positive")
	}

	bigMax := big.NewInt(int64(max))
	n, err := rand.Int(rand.Reader, bigMax)
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

// containsRune checks if a string contains a specific rune
func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
