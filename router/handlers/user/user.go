package user

import (
	"authenticationService/app"
	//"authenticationService/logger"
	"authenticationService/models"
	"encoding/json"
	"fmt"
	//"log/slog"
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

		log := a.Logger.With().
			Str("handler", "createUser").
			Str("name_process", name_process).
			Str("request_id", middleware.GetReqID(r.Context())).
			Logger()
		

		var req Request

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Error().Err(err).Msg("failed to decode request")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: err.Error(),
			})

			return
		}

		log.Info().Interface("request", req).Msg("request decoded")

		if err := validator.New().Struct(req); err != nil {
			log.Error().Err(err).Msg("failed to validate request")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: err.Error(),
			})

			return
		}

		log.Info().Interface("request", req).Msg("request validated")

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
			log.Error().Err(err).Msg("failed to create user")

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: fmt.Sprintf("failed to create user: %s", err.Error()),
			})

			return
		}

		// Возвращаем GUID созданного пользователя
		log.Info().Interface("GUID", newUser.ID).Msg("user created")

		w.WriteHeader(http.StatusCreated)

		render.JSON(w, r, Response{
			GUID: newUser.ID,
		})

		return
	}
}
