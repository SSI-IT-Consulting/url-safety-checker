package services

import (
	"context"

	"github.com/SSI-IT-Consulting/url-safety-checker.git/models"
	"gorm.io/gorm"
)

func CheckIfPrefixExistsInDb(ctx context.Context, db *gorm.DB, prefixes []string, safeSoFar []string) ([]string, map[string]string, error) {
	var fromDb []models.HashEntries
	if err := db.Where("prefix_hash IN ?", prefixes).
		Find(&fromDb).Error; err != nil {
		return nil, nil, err
	}

	existsInDb := make(map[string]bool)
	for _, hash := range fromDb {
		existsInDb[hash.PrefixHash] = true
	}

	safeUrls := make([]string, 0)
	unsafePrefixes := make(map[string]string)

	for i, fullHash := range safeSoFar {
		if existsInDb[prefixes[i]] {
			unsafePrefixes[prefixes[i]] = fullHash
		} else {
			safeUrls = append(safeUrls, fullHash)
		}
	}

	return safeUrls, unsafePrefixes, nil
}
