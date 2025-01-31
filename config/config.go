package config

import (
	"log"

	"github.com/joho/godotenv"
)

func LoadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("error loading environment variables")
	}
	log.Println("loaded environment variables")
}
