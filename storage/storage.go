package storage

import (
	"authenticationService/models"
	"errors"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type TokenKeeper interface {
	CreateUser(user *models.User) error
	CreateToken(refreshToken *models.Token) error
	GetUserByID(id string) (*models.User, error)
	GetTokenByJTI(JTI string) (*models.Token, error)
	GetTokensByUserId(userID string) ([]models.Token, error)
	UpdateRefreshTokenStatus(JTI, newStatus string) error
}
