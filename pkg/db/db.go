package db

import (
	"errors"
	"log"

	"github.com/codepnw/go-csrf/pkg/db/models"
	"github.com/codepnw/go-csrf/pkg/utils"
)

var users = map[string]models.User{}

var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}

func StoreUser(username, password, role string) (uuid string, err error) {
	uuid, err = utils.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	u := models.User{}
	for u != users[uuid] {
		uuid, err = utils.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	passwordHash, hashErr := utils.GenerateHashPassword(password)
	if hashErr != nil {
		err = hashErr
		return
	}

	users[uuid] = models.User{Username: username, PasswordHash: passwordHash, Role: role}

	return uuid, err
}

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	} else {
		return u, errors.New("User not found that matches given uuid")
	}
}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not found that matches given username")
}

func StoreRefreshToken() (jti string, err error) {
	jti, err = utils.GenerateRandomString(32)
	if err != nil {
		return jti, err
	}

	for refreshTokens[jti] != "" {
		jti, err = utils.GenerateRandomString(32)
		if err != nil {
			return jti, err
		}
	}

	refreshTokens[jti] = "valid"
	return jti, err
}

func DeleteRefreshToken(jti string) {
	delete(refreshTokens, jti)
}

func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti] != ""
}

func LogUserIn(username, password string) (models.User, string, error) {
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)
	if userErr != nil {
		return models.User{}, "", userErr
	}

	return user, uuid, utils.CheckPasswordAgainstHash(user.PasswordHash, password)
}

