package store

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/SSI-IT-Consulting/url-safety-checker.git/models"
	"github.com/redis/go-redis/v9"
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
	db := ConnectDB()
	rdb := ConnectRedis()

	return db, rdb
}

func ConnectDB() *gorm.DB {
	dsn := os.Getenv("DB_URL")

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecting to database ...")
	}

	psqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to access underlying DB: %s", err)
	}

	psqlDB.SetMaxOpenConns(50)
	psqlDB.SetMaxIdleConns(25)
	psqlDB.SetConnMaxLifetime(5 * time.Minute)

	db.AutoMigrate(&models.HashEntries{})

	log.Println("database connected successfully ...")
	return db
}

func ConnectRedis() *redis.Client {
	opt, _ := redis.ParseURL(os.Getenv("REDIS_URL"))
	rdb := redis.NewClient(opt)

	ctx := context.Background()
	rdb.SetNX(ctx, IDX, "0", 0)
	rdb.SetNX(ctx, StateMalware, "", 0)
	rdb.SetNX(ctx, StateSocialEngineering, "", 0)
	rdb.SetNX(ctx, StateUnwantedSoftware, "", 0)

	log.Println("redis connected successfully ...")
	return rdb
}

func GetEnvInt(key string) int {
	val := os.Getenv(key)
	res, err := strconv.Atoi(val)
	if err != nil {
		log.Fatal(err)
	}
	return res
}
