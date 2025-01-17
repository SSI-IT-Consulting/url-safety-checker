package main

import (
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/minodr/url-safety-checker.git/config"
	"github.com/minodr/url-safety-checker.git/controllers"
	"github.com/minodr/url-safety-checker.git/services"
	"github.com/minodr/url-safety-checker.git/store"
	"github.com/pterm/pterm"
)

const (
	MAX_DB_CONNECTIONS   = 20
	MAX_IDLE_CONNECTIONS = 50
	MAX_CONN_LIFETIME    = 5
)

func main() {
	config.LoadConfig()
	db, rdb := store.Connect()

	pterm.Info.Println("fetch update service running in background ...")
	services.FetchUpdates(db, rdb)

	// Configure database connection pooling
	sqlDB, err := db.DB()
	if err != nil {
		pterm.Fatal.Println("failed to configure database pooling: ", err)
	}

	sqlDB.SetMaxOpenConns(MAX_DB_CONNECTIONS)
	sqlDB.SetMaxIdleConns(MAX_IDLE_CONNECTIONS)
	sqlDB.SetConnMaxLifetime(MAX_CONN_LIFETIME * time.Minute)
	defer sqlDB.Close()

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.POST("api/check-url", controllers.CheckURLSafety(db, rdb))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router.Run("0.0.0.0:" + port)
}
