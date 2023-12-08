package server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/codepnw/go-csrf/module/middleware"
)

func StartServer(host, port string) error {
	h := fmt.Sprintf("%s:%s", host, port)
	
	log.Printf("server listening on: %s", h)
	
	handler := middleware.NewHandler()
	
	http.Handle("/", handler)
	return http.ListenAndServe(h, nil)
}