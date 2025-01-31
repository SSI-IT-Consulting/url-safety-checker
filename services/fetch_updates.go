package services

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const (
	backOffInterval     = 3 * time.Second
	breakTime           = 5 * time.Minute
	defaultWaitDuration = 30 * time.Minute
)

func FetchUpdates(ctx context.Context, db *gorm.DB, rdb *redis.Client) {
	go func() {
		for {
			err := GetPrefixHashes(ctx, db, rdb)
			if err == nil {
				time.Sleep(breakTime)
			} else {
				time.Sleep(defaultWaitDuration)
			}
		}
	}()
}
