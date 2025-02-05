package services

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/redis/go-redis/v9"
)

func LoadTXTAndStoreURLs(ctx context.Context, rdb *redis.Client, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	pipe := rdb.Pipeline()
	count := 0

	for scanner.Scan() {
		rawURL := strings.TrimSpace(scanner.Text()) // Read full line, remove spaces
		if rawURL == "" {
			continue // Skip empty lines
		}

		canonicalizedURL, err := canonicalizeURL(rawURL)
		if err != nil {
			log.Printf("Skipping invalid URL (%s): %v\n", rawURL, err)
			continue
		}

		// Hash URL for better storage key format
		hash := sha256.Sum256([]byte(canonicalizedURL))
		encodedHash := base64.StdEncoding.EncodeToString(hash[:])

		log.Println(canonicalizedURL, encodedHash)

		threatInfo := fmt.Sprintf("%s:BLACKLISTED_URL", filename)
		pipe.SetNX(ctx, encodedHash, threatInfo, 0)
		count++

		if count%1000 == 0 {
			if _, err := pipe.Exec(ctx); err != nil {
				log.Println("Failed to store a batch of URLs in Redis")
			}
			pipe = rdb.Pipeline()
		}
	}

	if count > 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			log.Println("Failed to store a batch of URLs in Redis")
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	fmt.Printf("Blacklist URLs successfully loaded and stored: %v urls in total from %s\n", count, filename)
	return nil
}

// Function to canonicalize URLs
func canonicalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

	// If the URL starts with a dot, remove it
	if yes := strings.HasPrefix(raw, "."); yes {
		raw = raw[1:]
	}

	parsedURL, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	// Normalize scheme
	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https" // Default to https if missing
	}

	// Normalize host
	parsedURL.Host = strings.ToLower(parsedURL.Host)

	// Remove fragment (not relevant for security checks)
	parsedURL.Fragment = ""

	// Normalize path
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	} else if !strings.HasSuffix(parsedURL.Path, "/") {
		parsedURL.Path = parsedURL.Path + "/"
	}

	return parsedURL.String(), nil
}

// Regular expression to match potential URLs in text
var urlRegex = regexp.MustCompile(`https?://[^\s/$.?#].[^\s]*|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?`)

// LoadCSVAndStoreURLs loads a CSV file, extracts valid URLs, canonicalizes them, and stores them in Redis.
func LoadCSVAndStoreURLs(ctx context.Context, rdb *redis.Client, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read CSV file row by row
	var count int
	pipe := rdb.Pipeline()
	batchSize := 1000

	for {
		record, err := reader.Read()
		if err != nil {
			break // Stop on EOF
		}

		// Iterate over each column value in the row
		for _, cell := range record {
			cell = strings.TrimSpace(cell)
			if cell == "" {
				continue // Skip empty cells
			}

			// Check if the value is a valid URL
			if isValidURL(cell) {
				canonicalURL, err := canonicalizeURL(cell)
				if err == nil {
					// Hash URL for better storage key format
					hash := sha256.Sum256([]byte(canonicalURL))
					encodedHash := base64.StdEncoding.EncodeToString(hash[:])

					log.Println("Storing URL:", canonicalURL, "with key:", encodedHash)

					// Use SetNX to ensure key is stored only if it doesn't already exist
					threatInfo := fmt.Sprintf("%s:BLACKLISTED_URL", filename)
					pipe.SetNX(ctx, encodedHash, threatInfo, 0)
					count++

					// Execute batch every batchSize items
					if count%batchSize == 0 {
						if _, err := pipe.Exec(ctx); err != nil {
							log.Println("Failed to store a batch of URLs in Redis:", err)
						}
						pipe = rdb.Pipeline() // Reset pipeline for the next batch
					}
				}
			}
		}
	}

	// Execute any remaining commands in the pipeline
	if count%batchSize != 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			log.Println("Failed to store the final batch of URLs in Redis:", err)
		}
	}

	log.Printf("Successfully stored %d blacklisted URLs in Redis from %s.\n", count, filename)
	return nil
}

// isValidURL checks whether a string is a valid URL using regex
func isValidURL(text string) bool {
	matches := urlRegex.FindAllString(text, -1)
	return len(matches) > 0
}
