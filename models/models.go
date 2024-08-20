package models

import "time"

type User struct {
	ID                          string `json:"id"`
	Name                        string `json:"name"`
	Email                       string `json:"email"`
	MaxActiveTokenPairs         int    `json:"max_active_token_pairs"`
	AccessTokenLifetimeMinutes  int    `json:"access_token_lifetime_minutes"`
	RefreshTokenLifetimeMinutes int    `json:"refresh_token_lifetime_minutes"`
	CreatedAt                   string `json:"created_at"`
	UpdatedAt                   string `json:"updated_at"`
}

type Token struct {
	JTI                   string    `json:"jti"`
	UserID                string    `json:"user_id"`
	RefreshTokenHash      string    `json:"refresh_token_hash"`
	IPAddress             string    `json:"ip_address"`
	RefreshTokenStatus    string    `json:"refresh_token_status"`
	CreatedAt             time.Time `json:"created_at"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}
