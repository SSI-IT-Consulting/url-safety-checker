package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const (
	prefixSize     = 4
	CLIENT_ID      = "url-safety-checker"
	CLIENT_VERSION = "1.0.0"

	ThreatTypes      = "MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE"
	PlatformTypes    = "ANY_PLATFORM"
	ThreatEntryTypes = "URL"

	FULL_HASH_URL = "https://safebrowsing.googleapis.com/v4/fullHashes:find?key="
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

func GetMatchingFullHashes(ctx context.Context, db *gorm.DB, rdb *redis.Client, prefixMap map[string]string) (map[string]string, error) {
	var threatEntries []ThreatEntry
	for prefix := range prefixMap {
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

	matchingFullHashes, err := AskGoogleForFullHashes(payload)
	if err != nil {
		return nil, err
	}

	unsafeUrls := make(map[string]string)
	pipe := rdb.Pipeline()

	for _, match := range matchingFullHashes.Matches {
		cacheDuration, err := time.ParseDuration(match.CacheDuration)
		if err == nil {
			pipe.Set(ctx, match.Threat.Hash, match.ThreatType, cacheDuration)
		}
		threatType := fmt.Sprintf("google:%s", match.ThreatType)
		unsafeUrls[match.Threat.Hash] = threatType
	}

	if _, err := pipe.Exec(ctx); err != nil {
		log.Println("error caching the matching full hashes")
	}

	return unsafeUrls, nil
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
