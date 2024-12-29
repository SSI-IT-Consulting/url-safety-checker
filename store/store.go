package store

import (
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
	db := ConnectDB()
	rdb := ConnectRedis()

	pterm.Success.Println("redis connected successfully ...")
	return db, rdb
}

func ConnectDB() *gorm.DB {
	dsn := os.Getenv("DB_URL")

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecting to database ...")
	}

	db.AutoMigrate(&models.HashEntries{})

	pterm.Success.Println("database connected successfully ...")
	return db
}

func ConnectRedis() *redis.Client {
	opt, _ := redis.ParseURL(os.Getenv("REDIS_URL"))
	rdb := redis.NewClient(opt)

	rdb.SetNX(rdb.Context(), IDX, "0", 0)
	rdb.SetNX(rdb.Context(), StateMalware, "", 0)
	rdb.SetNX(rdb.Context(), StateSocialEngineering, "", 0)
	rdb.SetNX(rdb.Context(), StateUnwantedSoftware, "", 0)

	pterm.Success.Println("redis connected successfully ...")

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
