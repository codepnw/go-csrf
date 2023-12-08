package main

import (
	"log"

	"github.com/codepnw/go-csrf/module/server"
	"github.com/codepnw/go-csrf/pkg/db"
	"github.com/codepnw/go-csrf/pkg/jwt"
)

const (
	host = "127.0.0.1"
	port = "9000"
)

func main() {
	db.InitDB()

	err := jwt.InitJWT()
	if err != nil {
		log.Println("error initializing JWT!")
		log.Fatal(err)
	}

	err = server.StartServer(host, port)
	if err != nil {
		log.Println("error starting server!")
		log.Fatal(err)
	}
}
