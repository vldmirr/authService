package jwtlib

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const refreshTokenLength = 32

type JWTClaims struct {
	ClientIp  string    `json:"client_ip"`
	ExpiresAt time.Time `json:"exp_at"`
	jwt.RegisteredClaims
}

func NewJWT(ip string, accessTokenDeadline time.Time) *jwt.Token {
	claims := JWTClaims{
		ClientIp:  ip,
		ExpiresAt: accessTokenDeadline,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       uuid.New().String(),
			Issuer:   "authenticationService",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token
}

func GenerateRefreshToken(accessToken string) (string, error) {
	const name_process = "jwtlib.GenerateRefreshToken"

	token := make([]byte, refreshTokenLength-7)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("%s: %w", name_process, err)
	}

	// Добавляем к refresh-токену последние 7 символов access-токена для связи
	return hex.EncodeToString(token) + accessToken[len(accessToken)-7:], nil
}

func ValidateToken(secretKey, tokenString string) (*jwt.Token, error) {
	const name_process = "jwtlib.ValidateToken"
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%s: unexpected signing method: %v", name_process, token.Header["alg"])
		}
		return []byte(secretKey), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Name}))
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("%s: %w", name_process, err)
	}

	if _, ok := token.Claims.(*JWTClaims); !ok || !token.Valid {
		fmt.Println(ok, token.Valid)
		return nil, fmt.Errorf("%s: token is invalid", name_process)
	}

	return token, nil
}
