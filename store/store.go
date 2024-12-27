package store

import (
	"context"
	"log"
	"os"
	"strconv"

	"github.com/go-redis/redis/v8"
	"github.com/minodr/url-safety-checker.git/models"
	"github.com/pterm/pterm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	IDX                    = "idx"
	StateMalware           = "state:MALWARE"
	StateSocialEngineering = "state:SOCIAL_ENGINEERING"
	StateUnwantedSoftware  = "state:UNWANTED_SOFTWARE"
)

func Connect() (*gorm.DB, *redis.Client) {
	dsn := os.Getenv("DB_URL")
	pterm.Info.Printf("connecting to postgres = \"%v\"\n", dsn)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecting to database ...")
	}

	db.AutoMigrate(&models.HashEntries{})

	pterm.Success.Println("database connected successfully ...")

	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Username: os.Getenv("REDIS_USERNAME"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       GetEnvInt("REDIS_DB"),
	})

	_, err = rdb.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal("error connecting to redis ...")
	}

	rdb.SetNX(rdb.Context(), IDX, "0", 0)
	rdb.SetNX(rdb.Context(), StateMalware, "", 0)
	rdb.SetNX(rdb.Context(), StateSocialEngineering, "", 0)
	rdb.SetNX(rdb.Context(), StateUnwantedSoftware, "", 0)

	pterm.Success.Println("redis connected successfully ...")
	return db, rdb
}

func GetEnvInt(key string) int {
	val := os.Getenv(key)
	res, err := strconv.Atoi(val)
	if err != nil {
		log.Fatal(err)
	}
	return res
}
