package jwt

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/codepnw/go-csrf/pkg/db"
	"github.com/codepnw/go-csrf/pkg/db/models"
	"github.com/dgrijalva/jwt-go"
)

const (
	privateKeyPath = "./keys/app.rsa"
	publicKeyPath  = "./keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewToken(uuid, role string) (authToken, refreshToken, csrfSecret string, err error) {
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	refreshToken, err = createRefreshToken(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	authToken, err = createAuthToken(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	return
}

func createAuthToken(uuid string, role string, csrfSecret string) (authToken string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}

	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)

	authToken, err = authJwt.SignedString(signKey)
	return
}

func createRefreshToken(uuid string, role string, csrfString string) (refreshTokenString string, err error) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}

	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		},
		Role: role,
		Csrf: csrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}
