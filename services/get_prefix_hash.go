package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/SSI-IT-Consulting/url-safety-checker.git/models"
	"github.com/redis/go-redis/v9"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	numWorkers      = 10
	batchSize       = 100
	PREFIX_HASH_URL = "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key="
)

type DataEntry struct {
	Hash  []byte `json:"hash"`
	Index uint   `json:"index"`
}

type Client struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type Constraints struct {
	MaxUpdateEntries      int      `json:"maxUpdateEntries"`
	MaxDatabaseEntries    int      `json:"maxDatabaseEntries"`
	SupportedCompressions []string `json:"supportedCompressions"`
}

type ListUpdateRequest struct {
	ThreatType      string      `json:"threatType"`
	PlatformType    string      `json:"platformType"`
	ThreatEntryType string      `json:"threatEntryType"`
	State           string      `json:"state"`
	Constraints     Constraints `json:"constraints"`
}

type PrefixHashRequest struct {
	Client             Client              `json:"client"`
	ListUpdateRequests []ListUpdateRequest `json:"listUpdateRequests"`
}

type RawHashes struct {
	PrefixSize int    `json:"prefixSize"`
	RawHashes  string `json:"rawHashes"`
}

type Additions struct {
	CompressionType string    `json:"compressionType"`
	RawHashes       RawHashes `json:"rawHashes"`
}

type RawIndices struct {
	Indices []int `json:"indices"`
}

type Removals struct {
	CompressionType string     `json:"compressionType"`
	RawIndices      RawIndices `json:"rawIndices"`
}

type CheckSum struct {
	Sha256 string `json:"sha256"`
}

type ListUpdateResponse struct {
	ThreatType      string      `json:"threatType"`
	ThreatEntryType string      `json:"threatEntryType"`
	PlatformType    string      `json:"platformType"`
	ResponseType    string      `json:"responseType"`
	Additions       []Additions `json:"additions"`
	Removals        []Removals  `json:"removals"`
	NewClientState  string      `json:"newClientState"`
	CheckSum        CheckSum    `json:"checksum"`
}

type PrefixHashResponse struct {
	ListUpdateResponses []ListUpdateResponse `json:"listUpdateResponses"`
	MinimumWaitDuration string               `json:"minimumWaitDuration"`
}

func CreateListUpdateRequest(ctx context.Context, rdb *redis.Client, threatType string) ListUpdateRequest {
	currentState, err := rdb.Get(ctx, "state:"+threatType).Result()
	if err != nil {
		log.Fatalf("error getting state for %s: %v", threatType, err)
	}

	return ListUpdateRequest{
		ThreatType:      threatType,
		PlatformType:    PlatformTypes,
		ThreatEntryType: ThreatEntryTypes,
		State:           currentState,
		Constraints: Constraints{
			MaxUpdateEntries:      2048,
			MaxDatabaseEntries:    4096,
			SupportedCompressions: []string{"RAW"},
		},
	}
}

func GetPrefixHashes(ctx context.Context, db *gorm.DB, rdb *redis.Client) error {
	for {
		payload := PrefixHashRequest{
			Client: Client{
				ClientID:      CLIENT_ID,
				ClientVersion: CLIENT_VERSION,
			},
			ListUpdateRequests: []ListUpdateRequest{
				CreateListUpdateRequest(ctx, rdb, "MALWARE"),
				CreateListUpdateRequest(ctx, rdb, "SOCIAL_ENGINEERING"),
				CreateListUpdateRequest(ctx, rdb, "UNWANTED_SOFTWARE"),
			},
		}

		response, err := AskGoogleForHashPrefixes(ctx, payload)
		if err != nil {
			return fmt.Errorf("error getting prefix hashes: %s", err)
		}

		pipe := rdb.Pipeline()

		for _, res := range response.ListUpdateResponses {
			for _, rawHashes := range res.Additions {
				decodedHash, _ := base64.StdEncoding.DecodeString(rawHashes.RawHashes.RawHashes)
				SavePrefixHashes(ctx, db, rdb, decodedHash, rawHashes.RawHashes.PrefixSize)
			}

			for _, removal := range res.Removals {
				RemovePrefixHashes(ctx, db, removal.RawIndices.Indices)
			}

			pipe.Set(ctx, "state:"+res.ThreatType, res.NewClientState, 0)
		}

		if _, err := pipe.Exec(ctx); err != nil {
			fmt.Errorf("error executing pipeline")
		}

		if len(response.ListUpdateResponses) == 0 {
			break
		}

		time.Sleep(backOffInterval)
	}

	return nil
}

func RemovePrefixHashes(ctx context.Context, db *gorm.DB, rawIndices []int) {
	wg := &sync.WaitGroup{}
	indexChannel := make(chan int, numWorkers)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go RemoveWorker(ctx, db, indexChannel, wg)
	}

	for _, idx := range rawIndices {
		indexChannel <- idx
	}

	close(indexChannel)
	wg.Wait()
}

func RemoveWorker(ctx context.Context, db *gorm.DB, indexChan <-chan int, wg *sync.WaitGroup) {
	defer wg.Done()

	var buffer []int
	for index := range indexChan {
		buffer = append(buffer, index)

		if len(buffer) >= batchSize {
			if err := db.Clauses(clause.OnConflict{DoNothing: true}).
				Where("index IN ?", buffer).Delete(&models.HashEntries{}).
				Error; err != nil {
				fmt.Errorf("failed to remove batch: %s", err)
			}
			buffer = buffer[:0]
		}
	}

	if len(buffer) > 0 {
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).
			Where("index IN ?", buffer).Delete(&models.HashEntries{}).
			Error; err != nil {
			fmt.Errorf("failed to remove batch: %v\n", err)
		}
	}
}

func SavePrefixHashes(ctx context.Context, db *gorm.DB, rdb *redis.Client, prefixHashes []byte, prefixSize int) {
	wg := &sync.WaitGroup{}
	prefixChannel := make(chan *DataEntry, numWorkers)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go AddWorker(ctx, db, prefixChannel, wg)
	}

	position, err := rdb.Get(ctx, "idx").Result()
	idx := 0
	if err == nil {
		idx, _ = strconv.Atoi(position)
	}

	for i := 0; i < len(prefixHashes); i += prefixSize {
		prefix := prefixHashes[i : i+prefixSize]
		idx += 1
		encodedPrefix := base64.StdEncoding.EncodeToString(prefix)
		prefixChannel <- &DataEntry{Hash: []byte(encodedPrefix), Index: uint(idx)}
	}

	rdb.Set(ctx, "idx", idx, 0)

	close(prefixChannel)
	wg.Wait()
}

func AddWorker(ctx context.Context, db *gorm.DB, prefixChan <-chan *DataEntry, wg *sync.WaitGroup) {
	defer wg.Done()

	var buffer []models.HashEntries
	for prefix := range prefixChan {
		buffer = append(buffer, models.HashEntries{
			PrefixHash: string(prefix.Hash),
			Index:      prefix.Index,
		})

		if len(buffer) >= batchSize {
			if err := db.Clauses(clause.OnConflict{DoNothing: true}).
				CreateInBatches(buffer, batchSize).Error; err != nil {
				fmt.Errorf("failed to insert batch: %v\n", err)
			}
			buffer = buffer[:0]
		}
	}

	if len(buffer) > 0 {
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).
			CreateInBatches(buffer, batchSize).Error; err != nil {
			fmt.Errorf("failed to insert batch: %v\n", err)
		}
	}
}

func AskGoogleForHashPrefixes(ctx context.Context, payload interface{}) (*PrefixHashResponse, error) {
	req, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request payload: %v", err)
	}

	url := PREFIX_HASH_URL + os.Getenv("GOOGLE_API_KEY")
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

	var response PrefixHashResponse
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	return &response, nil
}

func GeneratePrefixHash(ctx context.Context, fullHashes []string) ([]string, error) {
	prefixes := make([]string, 0)

	for _, fullHash := range fullHashes {
		hashBytes, err := base64.StdEncoding.DecodeString(fullHash)
		if err != nil {
			return nil, err
		}

		if len(hashBytes) < prefixSize {
			return nil, errors.New("hash is too short")
		}
		prefixes = append(prefixes, base64.StdEncoding.EncodeToString(hashBytes[:prefixSize]))
	}

	return prefixes, nil
}
