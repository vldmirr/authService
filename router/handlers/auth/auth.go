package auth

import (
	"authenticationService/app"
	jwtlib "authenticationService/jwt"
	"authenticationService/logger"
	"authenticationService/models"
	"authenticationService/storage"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type Request struct {
	GUID string `json:"GUID" validate:"required,uuid" binding:"required"`
}

type Response struct {
	Error        string `json:"error,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// @Summary Create new token pair
// @Description Returns a new access and refresh token pair
// @Accept json
// @Produce json
// @Param Request body Request true "Request"
// @Success 201 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /auth [post]
func New(a app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const name_process = "handlers.auth.New"

		log := a.Logger.With(
			slog.String("handler", "auth"),
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

		// Проверяем, что пользователь с указанным GUID существует в базе данных
		user, err := a.Storage.GetUserByID(req.GUID)
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrUserNotFound):
				log.Error("user not found", "GUID", req.GUID)

				w.WriteHeader(http.StatusBadRequest)

				render.JSON(w, r, Response{
					Error: "user not found",
				})
			default:
				log.Error("failed to get user by ID", logger.Err(err))

				w.WriteHeader(http.StatusInternalServerError)

				render.JSON(w, r, Response{
					Error: "internal server error",
				})
			}

			return
		}

		tokens, err := a.Storage.GetTokensByUserId(user.ID)
		if err != nil {
			log.Error("failed to get tokens by user ID", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		// Проверяем, что количество токенов у пользователя не превышает максимальное
		cntActiveAccessTokens := 0
		t1 := time.Now()
		for _, token := range tokens {
			if t1.Before(token.RefreshTokenExpiresAt) && token.RefreshTokenStatus == "unused" {
				cntActiveAccessTokens++
			}
		}
		if cntActiveAccessTokens >= user.MaxActiveTokenPairs {
			log.Error("user has reached the maximum number of active token pairs", "user_id", user.ID)

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: "user has reached the maximum number of active token pairs",
			})

			return
		}

		// Создаем новую пару токенов
		newToken := jwtlib.NewJWT(r.RemoteAddr, t1.Add(time.Duration(user.AccessTokenLifetimeMinutes)*time.Minute))
		signedToken, err := newToken.SignedString([]byte(a.Config.PrivateKey))
		if err != nil {
			log.Error("failed to sign access token", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		refreshToken, err := jwtlib.GenerateRefreshToken(signedToken)
		if err != nil {
			log.Error("failed to generate refresh token", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
		if err != nil {
			log.Error("failed to hash refresh token", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		// Сохраняем токены в базе данных
		if err := a.Storage.CreateToken(&models.Token{
			JTI:                   newToken.Claims.(jwtlib.JWTClaims).ID,
			UserID:                user.ID,
			RefreshTokenHash:      string(refreshTokenHash),
			IPAddress:             r.RemoteAddr,
			RefreshTokenStatus:    "unused",
			CreatedAt:             t1,
			AccessTokenExpiresAt:  t1.Add(time.Duration(user.AccessTokenLifetimeMinutes) * time.Minute),
			RefreshTokenExpiresAt: t1.Add(time.Duration(user.RefreshTokenLifetimeMinutes) * time.Minute),
		}); err != nil {
			log.Error("failed to create token", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		log.Info("token created", slog.Any("request", req))

		w.WriteHeader(http.StatusCreated)

		// Отправляем токены пользователю
		render.JSON(w, r, Response{
			AccessToken:  signedToken,
			RefreshToken: base64.StdEncoding.EncodeToString([]byte(refreshToken)),
		})

		log.Info("response sent", slog.Any("request", req))

		return
	}
}
