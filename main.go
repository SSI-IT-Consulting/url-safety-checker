package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SSI-IT-Consulting/url-safety-checker.git/config"
	"github.com/SSI-IT-Consulting/url-safety-checker.git/controllers"
	"github.com/SSI-IT-Consulting/url-safety-checker.git/services"
	"github.com/SSI-IT-Consulting/url-safety-checker.git/store"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	db, rdb := store.Connect()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load Blacklist URLs from file if provided
	if len(os.Args) > 1 {
		for i := 1; i < len(os.Args); i++ {
			go func(filename string) {
				err := services.LoadAndStoreURLs(ctx, rdb, filename)
				if err != nil {
					log.Printf("Error loading URLs from file %s: %v", filename, err)
				}
			}(os.Args[i])
			log.Printf("Started loading and storing URLs from file: %s", os.Args[i])
		}
	}

	// Run periodic updates for URL safety lists
	go services.FetchUpdates(ctx, db, rdb)
	log.Println("Fetch update service running in background...")

	// Setup HTTP server with Gin
	router := gin.Default()
	router.POST("api/check-url", controllers.CheckURLSafety(ctx, db, rdb))

	// Handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	go func() {
		log.Printf("Starting server on port %s...", port)
		if err := router.Run("0.0.0.0:" + port); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-stop
	log.Println("Shutting down gracefully...")

	// Close database connections
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.Close()
	}
	rdb.Close()
}
