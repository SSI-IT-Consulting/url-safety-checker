package store

import (
	"log"
	"os"
	"strconv"
	"time"

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

	// For redis
	PoolSize     = 50               // Maximum connections in the pool
	MinIdleConns = 10               // Minimum idle connections
	IdleTimeout  = 50 * time.Minute // Idle timeout for connections
	DialTimeout  = 50 * time.Second // Connection dial timeout
	ReadTimeout  = 30 * time.Second // Read timeout
	WriteTimeout = 30 * time.Second // Write timeout
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

	db.AutoMigrate(&models.HashEntries{})

	pterm.Success.Println("database connected successfully ...")
	return db
}

func ConnectRedis() *redis.Client {
	opt, _ := redis.ParseURL(os.Getenv("REDIS_URL"))
	rdb := redis.NewClient(opt)
	// rdb := redis.NewClient(&redis.Options{
	// 	Addr:         opt.Addr,
	// 	Password:     opt.Password,
	// 	DB:           opt.DB,
	// 	PoolSize:     PoolSize,
	// 	MinIdleConns: MinIdleConns,
	// 	IdleTimeout:  IdleTimeout,
	// 	DialTimeout:  DialTimeout,
	// 	ReadTimeout:  ReadTimeout,
	// 	WriteTimeout: WriteTimeout,
	// })

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
