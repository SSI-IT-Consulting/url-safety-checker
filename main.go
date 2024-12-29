package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/minodr/url-safety-checker.git/config"
	"github.com/minodr/url-safety-checker.git/controllers"
	"github.com/minodr/url-safety-checker.git/services"
	"github.com/minodr/url-safety-checker.git/store"
	"github.com/pterm/pterm"
)

func main() {
	config.LoadConfig()
	db, rdb := store.Connect()

	pterm.Info.Println("fetch update service running in background ...")
	services.FetchUpdates(db, rdb)

	router := gin.Default()

	router.POST("api/check-url", controllers.CheckURLSafety(db, rdb))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router.Run("0.0.0.0:" + port)
}
