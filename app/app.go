package app

import (
	"authenticationService/config"
	"authenticationService/storage"
	"github.com/rs/zerolog"
	//"github.com/rs/zerolog/log"
	"net/smtp"
)

type App struct {
	Config  *config.Config
	Logger  *zerolog.Logger
	Storage storage.TokenKeeper
	SMTP    smtp.Auth
}

func New(config *config.Config, storage storage.TokenKeeper, logger *zerolog.Logger, smtp smtp.Auth) *App {
	return &App{
		Config:  config,
		Logger:  logger,
		Storage: storage,
		SMTP:    smtp,
	}
}
