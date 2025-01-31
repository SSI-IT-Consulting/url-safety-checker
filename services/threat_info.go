package services

import (
	"context"

	"github.com/SSI-IT-Consulting/url-safety-checker.git/utils"
	"github.com/redis/go-redis/v9"
)

func GetThreatInfoFromCache(ctx context.Context, rdb *redis.Client, fullHashes []string, response *[]utils.Response) ([]string, error) {
	safeSoFar := make([]string, 0)

	for _, fullHash := range fullHashes {
		threat, err := rdb.Get(ctx, fullHash).Result()
		if err != nil && err != redis.Nil {
			return nil, err
		}

		if err == redis.Nil {
			safeSoFar = append(safeSoFar, fullHash)
		} else {
			*response = append(*response, utils.GenerateUnsafeResponse(fullHash, threat))
		}
	}

	return safeSoFar, nil
}
