package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codepnw/go-csrf/pkg/db"
	"github.com/codepnw/go-csrf/pkg/jwt"
	"github.com/codepnw/go-csrf/pkg/templates"
	"github.com/justinas/alice"
)

const (
	authToken    string = "AuthToken"
	refreshToken string = "RefreshToken"
	headerToken  string = "X-CSRF-Token"
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
			log.Println("in auth restrictedsection")

			cookie, err := r.Cookie("AuthToken")
			if err == http.ErrNoCookie {
				log.Println("unauthorized; auth no cookie!")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), http.StatusUnauthorized)
				return
			}

			if err != nil {
				log.Panicf("panic: %+v", err)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), http.StatusInternalServerError)
				return
			}

			ref, err := r.Cookie("RefreshToken")
			if err == http.ErrNoCookie {
				log.Println("unauthorized; no refresh cookie!")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			}

			if err != nil {
				log.Panicf("panic: %+v", err)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), http.StatusInternalServerError)
				return
			}

			reqCsrf := grabCsrfFromReq(r)
			log.Println(reqCsrf)

			auth, refAuth, csrf, err := jwt.CheckAndRefreshTokens(cookie.Value, ref.Value, reqCsrf)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("unauthorized; JWT not valid!")
					http.Error(w, http.StatusText(401), http.StatusUnauthorized)
					return
				}

				log.Panic("error not nil")
				log.Panicf("panic: %+v", err)
				http.Error(w, http.StatusText(500), http.StatusInternalServerError)
				return
			}

			log.Println("successfully recreated jwt!")

			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, auth, refAuth)
			w.Header().Set("X-CSRF-Token", csrf)
		default:
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{CsrfSecret: csrfSecret, SecretMessage: "Hello"})
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, err := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, err)

			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
			}

			token, refreshToken, csrf, err := jwt.CreateNewToken(uuid, user.Role)
			if err != nil {
				http.Error(w, http.StatusText(500), http.StatusInternalServerError)
			}

			setAuthAndRefreshCookies(&w, token, refreshToken)
			w.Header().Set(headerToken, csrf)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(500), http.StatusInternalServerError)
				}
				log.Println("uuid: " + uuid)

				authToken, refreshToken, csrfSecret, err := jwt.CreateNewToken(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authToken, refreshToken)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", 302)
	case "delete-user":
		log.Println("deleting user")

		auth, err := r.Cookie(authToken)
		if err == http.ErrNoCookie {
			log.Println("unauthorized; no auth cookie!")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "login", 302)
			return
		}

		if err != nil {
			log.Panicf("panic: %+v", err)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), http.StatusInternalServerError)
			return
		}

		uuid, err := jwt.GrabUUID(auth.Value)
		if err != nil {
			log.Panicf("panic: %+v", err)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), http.StatusInternalServerError)
			return
		}

		db.DeleteUser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/register", 302)

	default:
		w.WriteHeader(http.StatusOK)
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

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := optionsCookies(authToken, "")
	http.SetCookie(*w, &authCookie)

	refreshCookie := optionsCookies(refreshToken, "")
	http.SetCookie(*w, &refreshCookie)

	ref, err := r.Cookie(refreshToken)
	if err == http.ErrNoCookie {
		return
	}
	if err != nil {
		log.Panicf("panic: %+v", err.Error())
		http.Error(*w, http.StatusText(500), http.StatusInternalServerError)
	}

	jwt.RevokeRefreshToken(ref.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authToken, refreshToken string) {
	authCookie := optionsCookies(authToken, authToken)
	http.SetCookie(*w, &authCookie)

	refreshCookie := optionsCookies(refreshToken, refreshToken)
	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfForm := r.FormValue(headerToken)

	if csrfForm != "" {
		return csrfForm
	} else {
		return r.Header.Get(headerToken)
	}
}
