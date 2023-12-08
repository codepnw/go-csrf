package templates

import (
	"html/template"
	"log"
	"net/http"
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RestrictedPage struct {
	CsrfSecret    string
	SecretMessage string
}

const (
	tempLogin      string = "./pkg/templates/templateFiles/login.tmpl"
	tempRegister   string = "./pkg/templates/templateFiles/register.tmpl"
	tempRestricted string = "./pkg/templates/templateFiles/restricted.tmpl"
)

var templates = template.Must(template.ParseFiles(tempLogin, tempRegister, tempRestricted))

func RenderTemplate(w http.ResponseWriter, tmpl string, p any) {
	err := templates.ExecuteTemplate(w, tmpl+".tmpl", p)
	if err != nil {
		log.Printf("Temlate error here: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
