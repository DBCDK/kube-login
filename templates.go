package main

import (
	"encoding/base64"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var indexTmpl = template.Must(template.ParseFiles("html/index.html"))
var tokenTmpl = template.Must(template.ParseFiles("html/token.html"))

func renderIndex(w http.ResponseWriter) {
	renderTemplate(w, indexTmpl, nil)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getCAcertbase64() string {
	dat, err := ioutil.ReadFile(globalCApath)
	switch error := err.(type) {
	case *os.PathError:
		log.Printf("Error reading CA. File not found \"%s\"", globalCApath)
		dat = []byte("<error reading file>")
	default:
		_ = error

	}
	res := base64.StdEncoding.EncodeToString(dat)
	return res
}

func renderToken(w http.ResponseWriter, redirectURL, idToken, refreshToken string, claimobj Claim, a *app) {
	cacert := getCAcertbase64()
	renderTemplate(w, tokenTmpl, tokenTmplData{
		IDToken:      idToken,
		RefreshToken: refreshToken,
		RedirectURL:  redirectURL,
		CACert:       cacert,
		Name:         claimobj.Name,
		Email:        claimobj.Email,
		IssuerURL:    globalissuerURL,
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		APIServer:    globalapiServerURL,
	})
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(w, data)
	if err == nil {
		return
	}

	switch err := err.(type) {
	case *template.Error:
		// An ExecError guarantees that Execute has not written to the underlying reader.
		log.Printf("Error rendering template %s: %s", tmpl.Name(), err)

		// TODO(ericchiang): replace with better internal server error.
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		// An error with the underlying write, such as the connection being
		// dropped. Ignore for now.
	}
}
