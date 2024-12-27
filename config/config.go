package config

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/pterm/pterm"
)

func LoadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("error loading environment variables")
	}
	pterm.Success.Println("loaded environment variables")
}
