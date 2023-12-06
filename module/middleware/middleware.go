package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/justinas/alice"
)

const (
	authToken    string = "AuthToken"
	refreshToken string = "RefreshToken"
	formValue    string = "X-CSRF-Token"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panicf("recovered! panic: %+v", err)
				http.Error(w, http.StatusText(500), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "delete-user":
		default:
		}
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/logout":
	case "delete-user":
	default:
	}
}

func optionsCookies(name, v string) http.Cookie {
	var val string
	var exp time.Time
	if v == "" {
		val = ""
		exp = time.Now().Add(-1000 * time.Hour)
	}
	val = v

	return http.Cookie{
		Name:     name,
		Value:    val,
		Expires:  exp,
		HttpOnly: true,
	}
}

func nulltifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := optionsCookies(authToken, "")
	http.SetCookie(*w, &authCookie)

	refreshCookie := optionsCookies(refreshToken, "")
	http.SetCookie(*w, &refreshCookie)

	_, err := r.Cookie(refreshToken)
	if err == http.ErrNoCookie {
		return
	}  
	if err != nil {
		log.Panicf("panic: %+v", err.Error())
		http.Error(*w, http.StatusText(500), http.StatusInternalServerError)
	}
	
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authToken, refreshToken string) {
	authCookie := optionsCookies(authToken, authToken)
	http.SetCookie(*w, &authCookie)

	refreshCookie := optionsCookies(refreshToken, refreshToken)
	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfForm := r.FormValue(formValue)

	if csrfForm != "" {
		return csrfForm
	} else {
		return r.Header.Get(formValue)
	}
}
