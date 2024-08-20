package user

import (
	"authenticationService/app"
	"authenticationService/logger"
	"authenticationService/models"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Request struct {
	Name                        string `json:"name" validate:"required" binding:"required"`
	Email                       string `json:"email" validate:"required,email" binding:"required"`
	MaxActiveTokenPairs         int    `json:"max_active_token_pairs"`
	AccessTokenLifetimeMinutes  int    `json:"access_token_lifetime_minutes"`
	RefreshTokenLifetimeMinutes int    `json:"refresh_token_lifetime_minutes"`
}

type Response struct {
	GUID  string `json:"GUID,omitempty"`
	Error string `json:"error,omitempty"`
}

// @Summary Create a new user
// @Description Returns a new user GUID
// @Accept json
// @Produce json
// @Param Request body Request true "Request"
// @Success 201 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /users [post]
func New(a app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const name_process = "handlers.auth.New"

		log := a.Logger.With(
			slog.String("handler", "createUser"),
			slog.String("op", name_process),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Error("failed to decode request", logger.Err(err))

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: err.Error(),
			})

			return
		}

		log.Info("request decoded", slog.Any("request", req))

		if err := validator.New().Struct(req); err != nil {
			log.Error("failed to validate request", logger.Err(err))

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: err.Error(),
			})

			return
		}

		log.Info("request validated", slog.Any("request", req))

		if req.MaxActiveTokenPairs == 0 {
			req.MaxActiveTokenPairs = 5
		}
		if req.AccessTokenLifetimeMinutes == 0 {
			req.AccessTokenLifetimeMinutes = 60
		}
		if req.RefreshTokenLifetimeMinutes == 0 {
			req.RefreshTokenLifetimeMinutes = 129600
		}

		newUser := &models.User{
			ID:                          uuid.New().String(),
			Name:                        req.Name,
			Email:                       req.Email,
			MaxActiveTokenPairs:         req.MaxActiveTokenPairs,
			AccessTokenLifetimeMinutes:  req.AccessTokenLifetimeMinutes,
			RefreshTokenLifetimeMinutes: req.RefreshTokenLifetimeMinutes,
		}

		// Создаем пользователя в базе данных
		if err := a.Storage.CreateUser(newUser); err != nil {
			log.Error("failed to create user", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: fmt.Sprintf("failed to create user: %s", err.Error()),
			})

			return
		}

		// Возвращаем GUID созданного пользователя
		log.Info("user created", slog.String("GUID", newUser.ID))

		w.WriteHeader(http.StatusCreated)

		render.JSON(w, r, Response{
			GUID: newUser.ID,
		})

		return
	}
}
