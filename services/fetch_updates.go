package services

import (
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pterm/pterm"
	"gorm.io/gorm"
)

const (
	backOffInterval     = 3 * time.Second
	breakTime           = 5 * time.Minute
	defaultWaitDuration = 30 * time.Minute
)

func FetchUpdates(db *gorm.DB, rdb *redis.Client) {
	go func() {
		for {
			spinner, _ := pterm.DefaultSpinner.Start("fetching data from google api ...")
			err := GetPrefixHashes(db, rdb)
			if err == nil {
				spinner.Success("fetch from google api completed.")
				pterm.Info.Printf("waiting for %v before next fetch ...\n", breakTime)
				time.Sleep(breakTime)
			} else {
				spinner.Fail("fetch from google api failed.")
				pterm.Error.Printf("waiting for %v before retry ...\n", defaultWaitDuration)
				time.Sleep(defaultWaitDuration)
			}
		}
	}()
}
