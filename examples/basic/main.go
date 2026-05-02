package main

import (
	"fmt"
	"log"
	"os"

	hclconfig "github.com/caster-zip/hclconfig"
)

type Config struct {
	Database DatabaseConfig `hcl:"database,block"`
	App      AppConfig      `hcl:"app,block"`
}

type DatabaseConfig struct {
	Host string `hcl:"host,attr"`
	Port int    `hcl:"port,attr"`
}

type AppConfig struct {
	DBUrl string `hcl:"db_url,attr"`
	Env   string `hcl:"env,attr"`
}

func main() {
	// Set APP_ENV so the env() function has something to read
	if os.Getenv("APP_ENV") == "" {
		os.Setenv("APP_ENV", "development")
	}

	var cfg Config
	if err := hclconfig.LoadFile("config.hcl", &cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Database Host: %s\n", cfg.Database.Host)
	fmt.Printf("Database Port: %d\n", cfg.Database.Port)
	fmt.Printf("App DB URL:    %s\n", cfg.App.DBUrl)
	fmt.Printf("App Env:       %s\n", cfg.App.Env)
}
