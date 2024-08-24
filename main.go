package main

import (
	"authenticationService/app"
	"authenticationService/config"
	"authenticationService/logger"
	"authenticationService/router"
	smtplib "authenticationService/smtp"
	"authenticationService/storage/postgres"
	//"log/slog"
	"net/http"
	smtp2 "net/smtp"

	_ "github.com/lib/pq"
)

// @title authService API
// @version 1.1
// @host localhost:8000
// @BasePath /

func main() {
	cfg := config.MustLoad()

	log := logger.NewLogger(cfg.Env)

	log.Info().Interface("env", cfg.Env).Msg("Starting the application")

	storage, err := postgres.NewStorage(cfg.Storage)
	if err != nil {
		log.Error().Err(err).Msg("failed to create storage")
		return
	}

	log.Info().
    Str("host", cfg.Storage.Host).
    Int("port", cfg.Storage.Port).
    Str("database", cfg.Storage.Database).
    Msg("Connected PostgreSQL successfully")

	var smtp smtp2.Auth
	if cfg.SMTP.IsEnabled {
		smtp = smtplib.New(cfg.SMTP)
		log.Info().Msg("Connected SMTP successfully")
	} else {
		log.Info().Msg("SMTP is disabled")
	}

	a := app.New(cfg, storage, &log, smtp)

	router := server.New(*a)

	log.Info().Interface("address", cfg.Address).Msg("Server started")
	if err := http.ListenAndServe(cfg.Address, router); err != nil {
		log.Error().Err(err).Msg("failed to start server")
		return
	}

}
