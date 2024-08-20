package app

import (
	"authenticationService/config"
	"authenticationService/storage"
	"log/slog"
	"net/smtp"
)

type App struct {
	Config  *config.Config
	Logger  *slog.Logger
	Storage storage.TokenKeeper
	SMTP    smtp.Auth
}

func New(config *config.Config, storage storage.TokenKeeper, logger *slog.Logger, smtp smtp.Auth) *App {
	return &App{
		Config:  config,
		Logger:  logger,
		Storage: storage,
		SMTP:    smtp,
	}
}
