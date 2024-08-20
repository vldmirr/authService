package refresh

import (
	"authenticationService/app"
	jwtlib "authenticationService/jwt"
	"authenticationService/logger"
	"authenticationService/models"
	smtplib "authenticationService/smtp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type Request struct {
	AccessToken  string `json:"access_token" validate:"required" binding:"required"`
	RefreshToken string `json:"refresh_token" validate:"required" binding:"required"`
}

type Response struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// @Summary Refresh access token
// @Description Returns a new access token
// @Accept json
// @Produce json
// @Param Request body Request true "Request"
// @Success 201 {object} Response
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /refresh [post]
func New(a app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const name_process = "handlers.auth.New"

		log := a.Logger.With(
			slog.String("handler", "refresh"),
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

		decodedRefreshTokenBytes, err := base64.StdEncoding.DecodeString(req.RefreshToken)
		if err != nil {
			log.Error("failed to decode refresh token", logger.Err(err))

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: err.Error(),
			})

			return
		}

		decodedRefreshToken := string(decodedRefreshTokenBytes)

		// Проверяем, что последние 7 символов у refresh и access токенов совпадают
		if req.AccessToken[len(req.AccessToken)-7:] != decodedRefreshToken[len(decodedRefreshToken)-7:] {
			log.Error("access token and refresh token do not match")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: "access token and refresh token do not match",
			})

			return
		}

		log.Info("access token and refresh token match checked", slog.Any("request", req))

		decodedAccessToken, err := jwtlib.ValidateToken(a.Config.PrivateKey, req.AccessToken)
		if err != nil {
			log.Error("failed to validate access token", logger.Err(err))

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: err.Error(),
			})

			return
		}

		log.Info("access token validated", slog.Any("request", req))

		claims := decodedAccessToken.Claims.(*jwtlib.JWTClaims)

		// Проверяем что access токен истек
		t1 := time.Now()
		if t1.Before(claims.ExpiresAt) {
			log.Error("access token is not expired")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: "access token is not expired",
			})

			return
		}

		log.Info("access token expire checked", slog.Any("request", req))

		// Проверяем, что refresh токен не истек
		pair, err := a.Storage.GetTokenByJTI(claims.ID)
		fmt.Println(claims.ID)
		if err != nil {
			log.Error("failed to get token by JTI", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		if pair.RefreshTokenExpiresAt.Before(t1) {
			log.Error("refresh token is expired")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: "refresh token is expired",
			})

			return
		}

		log.Info("refresh token expire time checked", slog.Any("request", req))

		// Проверяем, что refresh токен не использован ранее
		if pair.RefreshTokenStatus == "used" {
			log.Error("refresh token is already used")

			w.WriteHeader(http.StatusBadRequest)

			render.JSON(w, r, Response{
				Error: "refresh token is already used",
			})

			return
		}

		log.Info("refresh token status checked", slog.Any("request", req))

		// Создаем новую пару токенов
		user, err := a.Storage.GetUserByID(pair.UserID)
		if err != nil {
			log.Error("failed to get user by ID", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

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

		log.Info("new tokens generated", slog.Any("request", req))

		// Меняем статус refresh токена на "used"
		if err := a.Storage.UpdateRefreshTokenStatus(claims.ID, "used"); err != nil {
			log.Error("failed to update token status", logger.Err(err))

			w.WriteHeader(http.StatusInternalServerError)

			render.JSON(w, r, Response{
				Error: "internal server error",
			})

			return
		}

		log.Info("refresh token status updated", slog.Any("request", req))

		// В случае смены ip отправляем письмо
		if claims.ClientIp != r.RemoteAddr && a.Config.SMTP.IsEnabled {
			if err := smtplib.SendEmail(a, user.Email, "IP address changed", "Your IP address has been changed. If it was not you, please contact us."); err != nil {
				log.Error("failed to send email", logger.Err(err))
			} else {
				log.Info("email notification sent", slog.Any("request", req))
			}
		}

		log.Info("client ip checked", slog.Any("request", req))

		// Сохраняем новые токены в базе данных
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

		log.Info("new token created", slog.Any("request", req))

		// Отправляем новые токены пользователю
		w.WriteHeader(http.StatusCreated)

		render.JSON(w, r, Response{
			AccessToken:  signedToken,
			RefreshToken: base64.StdEncoding.EncodeToString([]byte(refreshToken)),
		})

		return
	}
}
