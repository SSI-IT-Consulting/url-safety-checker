package services

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

func LoadAndStoreURLs(ctx context.Context, rdb *redis.Client, filename string) error {
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

		pipe.SetNX(ctx, encodedHash, "BLACKLISTED_URL", 0)
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
	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")

	return parsedURL.String(), nil
}
