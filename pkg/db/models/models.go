package models

import (
	"github.com/codepnw/go-csrf/pkg/utils"
	"github.com/dgrijalva/jwt-go"
	"time"
)

const (
	RefreshTokenValidTime = time.Hour * 72
	AuthTokenValidTime = time.Minute * 15
)

type User struct {
	 Username, PasswordHash, Role string
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

func GenerateCSRFSecret() (string, error) {
	return utils.GenerateRandomString(32)
}

