package server

import (
	"authenticationService/app"
	_ "authenticationService/docs"
	"authenticationService/logger"
	"authenticationService/router/handlers/auth"
	"authenticationService/router/handlers/refresh"
	"authenticationService/router/handlers/user"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

func New(a app.App) *chi.Mux {
	router := chi.NewRouter()

	router.Use(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Recoverer,
		middleware.URLFormat,
		logger.MiddlewareLogger(*a.Logger),
	)

	router.Post("/users", user.New(a))
	router.Post("/auth", auth.New(a))
	router.Post("/refresh", refresh.New(a))

	if a.Config.Env == "local" {
		router.Get("/swagger/*", httpSwagger.WrapHandler)
	}

	return router
}
