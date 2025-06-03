package main

import (
	"net/http"

	oidc "github.com/coreos/go-oidc"
)

//Claim The object that holds the claim exposing it to the template
type Claim struct {
	Iss           string   `json:"iss"`
	Sub           string   `json:"sub"`
	Aud           string   `json:"aud"`
	Exp           int      `json:"exp"`
	Iat           int      `json:"iat"`
	AtHash        string   `json:"at_hash"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
	Name          string   `json:"name"`
}

type app struct {
	clientID         string
	clientSecret     string
	clientSecretFile string
	redirectURI      string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool

	client *http.Client
}

// tokenTmplData struct to hold values for token template
type tokenTmplData struct {
	IDToken      string
	RefreshToken string
	RedirectURL  string
	Claims       string
	CACert       string
	Name         string
	Email        string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	APIServer    string
}
