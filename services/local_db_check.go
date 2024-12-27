package services

import (
	"github.com/go-redis/redis/v8"
	"github.com/minodr/url-safety-checker.git/models"
	"github.com/minodr/url-safety-checker.git/utils"
	"github.com/pterm/pterm"
	"gorm.io/gorm"
)

func CheckIfHashExistsInCache(db *gorm.DB, rdb *redis.Client, prefixes map[string]string) (map[string]bool, error) {
	var prefixHashes []string
	for _, prefix := range prefixes {
		prefixHashes = append(prefixHashes, prefix)
	}

	prefixHashesInterface := utils.StringSliceToInterface(prefixHashes)

	exists, err := rdb.SMIsMember(rdb.Context(),
		"prefixHashes", prefixHashesInterface...).Result()
	if err != nil {
		pterm.Error.Println(err)
		return nil, err
	}

	existingHashes := make(map[string]bool, len(prefixes))
	var toLocalCheckPrefixes []string

	for i, exist := range exists {
		existingHashes[prefixHashes[i]] = exist
		if !exist {
			toLocalCheckPrefixes = append(toLocalCheckPrefixes, prefixHashes[i])
		}
	}

	var hashEntries []models.HashEntries
	if len(toLocalCheckPrefixes) > 0 {
		if err := db.Where("prefix_hash IN ?", toLocalCheckPrefixes).
			Find(&hashEntries).Error; err != nil {
			pterm.Error.Println(err)
			return nil, err
		}
	}

	for _, hashEntry := range hashEntries {
		existingHashes[hashEntry.PrefixHash] = true
	}

	return existingHashes, nil
}
