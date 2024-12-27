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
	pterm.DefaultSection.Println("URL Safety Checker")

	config.LoadConfig()
	db, rdb := store.Connect()

	pterm.Info.Println("fetch update service running in background ...")
	services.FetchUpdates(db, rdb)

	router := gin.Default()

	router.POST("api/check-url", controllers.CheckURLSafety(db, rdb))

	serverAddr := os.Getenv("SERVER_ADDR")
	pterm.Info.Printf("server running on %s ...", serverAddr)
	router.Run(serverAddr)
}
