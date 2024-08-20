package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Env        string `yaml:"env" env-required:"true"`
	SMTP       `yaml:"smtp" env-required:"true"`
	PrivateKey string `yaml:"private_key" env-required:"true"`
	Storage    `yaml:"storage" env-required:"true"`
	Server     `yaml:"http_server" env-required:"true"`
}

type SMTP struct {
	IsEnabled   bool   `yaml:"is_enabled" env-default:"false"`
	Host        string `yaml:"host"`
	Port        string `yaml:"port"`
	PublicKey   string `yaml:"mailjet_public_key"`
	PrivateKey  string `yaml:"mailjet_private_key"`
	SenderEmail string `yaml:"mailjet_sender_email"`
}

type Server struct {
	Address string `yaml:"address" env-default:"localhost:8000"`
}

type Storage struct {
	Host     string `yaml:"POSTGRES_HOST" env-required:"true"`
	Port     int    `yaml:"POSTGRES_PORT" env-required:"true"`
	User     string `yaml:"POSTGRES_USER" env-required:"true"`
	Password string `yaml:"POSTGRES_PASSWORD" env-required:"true"`
	Database string `yaml:"POSTGRES_DB" env-required:"true"`
}

func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config/config.yaml"
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic(fmt.Sprintf("config file not found: %s", configPath))
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		panic(err)
	}

	var cfg Config
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		panic(err)
	}

	return &cfg
}
