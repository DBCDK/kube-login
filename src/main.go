package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"path/filepath"
)

const webrootPath = "html"

var (
	globalCApath       string
	globalissuerURL    string
	globalapiServerURL string
)

var (
	a         app
	issuerURL string
	listen    string
	tlsCert   string
	tlsKey    string
	rootCAs   string
	debug     bool
)

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

func cmd() *cobra.Command {

	c := cobra.Command{
		Use:   "agi-login",
		Short: "Agillic DEX login client",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("surplus arguments provided")
			}

			u, err := url.Parse(a.redirectURI)
			if err != nil {
				return fmt.Errorf("parse redirect-uri: %v", err)
			}
			listenURL, err := url.Parse(listen)
			if err != nil {
				return fmt.Errorf("parse listen address: %v", err)
			}

			if rootCAs != "" {
				client, err := httpClientForRootCAs(rootCAs)
				if err != nil {
					return err
				}
				globalCApath = rootCAs
				a.client = client
			}

			if debug {
				if a.client == nil {
					a.client = &http.Client{
						Transport: debugTransport{http.DefaultTransport},
					}
				} else {
					a.client.Transport = debugTransport{a.client.Transport}
				}
			}

			if a.client == nil {
				a.client = http.DefaultClient
			}

			if err := configureApp(); err != nil {
				panic(err)
			}

			http.HandleFunc("/res/", a.handleStaticResource)
			http.HandleFunc("/login", a.handleLogin)
			http.HandleFunc("/", a.handleIndex)
			http.HandleFunc(u.Path, a.handleCallback)

			switch listenURL.Scheme {
			case "http":
				log.Printf("listening on %s", listen)
				return http.ListenAndServe(listenURL.Host, nil)
			case "https":
				log.Printf("listening on %s", listen)
				return http.ListenAndServeTLS(listenURL.Host, tlsCert, tlsKey, nil)
			default:
				return fmt.Errorf("listen address %q is not using http or https", listen)
			}
		},
	}
	c.Flags().StringVar(&globalapiServerURL, "api-server", "https://127.0.0.1", "URL to kubernetes API to present in generated kubectl config")
	c.Flags().StringVar(&a.clientID, "client-id", "kube-login", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&a.clientSecret, "client-secret", "", "OAuth2 client secret of this application.")
	c.Flags().StringVar(&a.clientSecretFile, "client-secret-file", "/path/to/client.secret", "OAuth2 client secret of this application (read from a file).")
	c.Flags().StringVar(&a.redirectURI, "redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	c.Flags().StringVar(&issuerURL, "issuer", "https://127.0.0.1:5556", "URL of the OpenID Connect issuer.")
	c.Flags().StringVar(&listen, "listen", "http://127.0.0.1:5555", "HTTP(S) address to listen at.")
	c.Flags().StringVar(&tlsCert, "tls-cert", "", "X509 cert file to present when serving HTTPS.")
	c.Flags().StringVar(&tlsKey, "tls-key", "", "Private key for the HTTPS cert.")
	c.Flags().StringVar(&rootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
	c.Flags().BoolVar(&debug, "debug", false, "Print all request and responses from the OpenID Connect issuer.")

	return &c
}

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func configureApp() error {
	// TODO(ericchiang): Retry with backoff
	ctx := oidc.ClientContext(context.Background(), a.client)
	globalissuerURL = issuerURL
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return fmt.Errorf("Failed to query provider %q: %v", issuerURL, err)
	}

	var s struct {
		// What scopes does a provider support?
		//
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := provider.Claims(&s); err != nil {
		return fmt.Errorf("Failed to parse provider scopes_supported: %v", err)
	}

	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		a.offlineAsScope = true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		a.offlineAsScope = func() bool {
			for _, scope := range s.ScopesSupported {
				if scope == oidc.ScopeOfflineAccess {
					return true
				}
			}
			return false
		}()
	}

	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})

	// if client secret is not set verbatim, try loading from file
	if a.clientSecret == "" {
		fileContent, err := ioutil.ReadFile(a.clientSecretFile)
		if err != nil {
			return err
		}

		a.clientSecret = strings.TrimSpace(string(fileContent))
	}

	return nil
}

func (a *app) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}
}

func (a *app) handleStaticResource(w http.ResponseWriter, r *http.Request) {
	req := r.URL.Path
	file := filepath.Join(webrootPath, req)

	if _, err := os.Stat(file); err == nil {
		http.ServeFile(w, r, file)
	} else {
		http.Error(w, fmt.Sprintf("File not found: %s", req), http.StatusNotFound)
	}
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	renderIndex(w)
}

func (a *app) handleIndex2(w http.ResponseWriter, r *http.Request) {
	//renderIndex(w)
	var scopes []string
	if extraScopes := r.FormValue("extra_scopes"); extraScopes != "" {
		scopes = strings.Split(extraScopes, " ")
	}
	var clients []string
	if crossClients := r.FormValue("cross_client"); crossClients != "" {
		clients = strings.Split(crossClients, " ")
	}
	for _, client := range clients {
		scopes = append(scopes, "audience:server:client_id:"+client)
	}

	authCodeURL := ""
	scopes = append(scopes, "openid", "profile", "email", "groups", "offline_access")
	authCodeURL = a.oauth2Config(scopes).AuthCodeURL("", oauth2.AccessTypeOffline)

	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {

	intent := r.FormValue("intent")
	if err := validateIntent(intent); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var scopes []string
	if extraScopes := r.FormValue("extra_scopes"); extraScopes != "" {
		scopes = strings.Split(extraScopes, " ")
	}
	var clients []string
	if crossClients := r.FormValue("cross_client"); crossClients != "" {
		clients = strings.Split(crossClients, " ")
	}
	for _, client := range clients {
		scopes = append(scopes, "audience:server:client_id:"+client)
	}

	authCodeURL := ""
	scopes = append(scopes, "openid", "profile", "email", "groups")
	if false { // TODO: Offline access is always allowed, for now
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(intent)
	} else if a.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(intent)
	} else {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(intent, oauth2.AccessTypeOffline)
	}

	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if err := validateIntent(r.FormValue("state")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
	case "POST":
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			http.Error(w, fmt.Sprintf("no refresh_token in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}
	var claims json.RawMessage
	var claimobj Claim
	idToken.Claims(&claims)
	jsonErr := json.Unmarshal([]byte(claims), &claimobj)
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "Json Error: %s\n", err)
	}

	renderToken(w, a.redirectURI, rawIDToken, token.RefreshToken, claimobj, a)
}

func validateIntent(intent string) error {
	switch intent {
	case "kubeconfig":
	case "dashboard":
	default:
		return fmt.Errorf("invalid intent: %s", intent)
	}

	return nil
}
