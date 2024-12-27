package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pterm/pterm"
	"gorm.io/gorm"
)

const (
	prefixSize     = 4
	CLIENT_ID      = "url-safety-checker"
	CLIENT_VERSION = "1.0.0"

	ThreatTypes      = "MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE"
	PlatformTypes    = "ANY_PLATFORM"
	ThreatEntryTypes = "URL"

	FULL_HASH_URL   = "https://safebrowsing.googleapis.com/v4/fullHashes:find?key="
)

type ThreatInfo struct {
	ThreatTypes      []string      `json:"threatTypes"`
	PlatformTypes    []string      `json:"platformTypes"`
	ThreatEntryTypes []string      `json:"threatEntryTypes"`
	ThreatEntries    []ThreatEntry `json:"threatEntries"`
}

type ThreatEntry struct {
	Hash string `json:"hash"`
}

type FullHashesRequest struct {
	Client       Client     `json:"client"`
	ClientStates []string   `json:"clientStates"`
	ThreatInfo   ThreatInfo `json:"threatInfo"`
}

type MetadataEntry struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type ThreatMetadata struct {
	Entries []MetadataEntry `json:"entries"`
}

type ThreatMatch struct {
	ThreatType          string         `json:"threatType"`
	PlatformType        string         `json:"platformType"`
	ThreatEntryType     string         `json:"threatEntryType"`
	Threat              ThreatEntry    `json:"threat"`
	ThreatEntryMetadata ThreatMetadata `json:"threatEntryMetadata"`
	CacheDuration       string         `json:"cacheDuration"`
}

type FullHashResponse struct {
	Matches               []ThreatMatch `json:"matches"`
	MinimumWaitDuration   string        `json:"minimumWaitDuration"`
	NegativeCacheDuration string        `json:"negativeCacheDuration"`
}

func GetMatchingFullHashes(db *gorm.DB, rdb *redis.Client, prefixes []string) (map[string][]ThreatEntry, error) {
	var threatEntries []ThreatEntry
	for _, prefix := range prefixes {
		threatEntries = append(threatEntries, ThreatEntry{Hash: prefix})
	}

	payload := FullHashesRequest{
		Client: Client{
			ClientID:      CLIENT_ID,
			ClientVersion: CLIENT_VERSION,
		},
		ClientStates: []string{},
		ThreatInfo: ThreatInfo{
			ThreatTypes:      strings.Split(ThreatTypes, ", "),
			PlatformTypes:    strings.Split(PlatformTypes, ", "),
			ThreatEntryTypes: strings.Split(ThreatEntryTypes, ", "),
			ThreatEntries:    threatEntries,
		},
	}

	serverFullHashes, err := AskGoogleForFullHashes(payload)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	err = rdb.SAdd(ctx, "prefixHashes", prefixes).Err()
	if err != nil {
		pterm.Error.Printf("error adding prefix hashes to cache: %v", err)
	}

	response := make(map[string][]ThreatEntry)
	pipe := rdb.Pipeline()
	for _, match := range serverFullHashes.Matches {
		cacheDuration, err := time.ParseDuration(match.CacheDuration)
		if err == nil {
			pipe.Set(ctx, "fullHash:"+match.Threat.Hash, match.ThreatType, cacheDuration)
		}
		response[match.Threat.Hash] = append(response[match.Threat.Hash], match.Threat)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		pterm.Error.Println("error executing pipeline")
	}

	return response, nil
}

func GeneratePrefixHash(fullHashes []string) (map[string]string, error) {
	response := make(map[string]string)

	for _, fullHash := range fullHashes {
		hashBytes, err := base64.StdEncoding.DecodeString(fullHash)
		if err != nil {
			return nil, err
		}

		if len(hashBytes) < prefixSize {
			return nil, errors.New("hash is too short")
		}
		response[fullHash] = base64.StdEncoding.EncodeToString(hashBytes[:prefixSize])
	}

	return response, nil
}

func AskGoogleForFullHashes(payload interface{}) (*FullHashResponse, error) {
	req, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request payload: %v", err)
	}

	url := FULL_HASH_URL + os.Getenv("GOOGLE_API_KEY")
	res, err := http.Post(url, "application/json", bytes.NewBuffer(req))
	if err != nil {
		return nil, fmt.Errorf("error making request to Safe Browsing API: %v", err)
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %d, body: %s", res.StatusCode, string(resBytes))
	}

	var response FullHashResponse
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	return &response, nil
}

func CompareFullHashes(urls []string, serverHashes map[string][]ThreatEntry) map[string]bool {
	response := make(map[string]bool)
	for _, url := range urls {
		isSafe := true
		for _, serverHash := range serverHashes[url] {
			if url == serverHash.Hash {
				isSafe = false
				break
			}
		}
		response[url] = isSafe
	}
	return response
}

func GetThreatInfoFromCache(rdb *redis.Client, fullHashes []string, threatType map[string]string) error {
	for _, fullHash := range fullHashes {
		threat, err := rdb.Get(rdb.Context(), "fullHash:"+fullHash).Result()
		if err != nil && err != redis.Nil {
			return err
		}
		threatType[fullHash] = threat
	}

	return nil
}
