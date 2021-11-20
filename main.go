package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type config struct {
	SESSION_SECRET string `validate:"required"`

	ISSUER        string `validate:"url,required"`
	CLIENT_ID     string `validate:"required"`
	CLIENT_SECRET string `validate:"required"`

	BIND_ADDRESS       string
	BASE_URL           string `validate:"url,required"`
	AUTH_CALLBACK_PATH string `validate:"required"`
	BACKEND_URL        string `validate:"required"`
}

var env config

var validate *validator.Validate

func init() {
	validate = validator.New()
	viper.SetEnvPrefix("OIDC_PROXY")
	viper.SetConfigType("dotenv")
	viper.AddConfigPath(".")
	viper.SetConfigName(".env")

	viper.BindEnv("SESSION_SECRET")
	viper.BindEnv("ISSUER")
	viper.BindEnv("CLIENT_ID")
	viper.BindEnv("CLIENT_SECRET")
	viper.BindEnv("BIND_ADDRESS")
	viper.BindEnv("BASE_URL")
	viper.BindEnv("AUTH_CALLBACK_PATH")
	viper.BindEnv("BACKEND_URL")
	viper.SetDefault("BIND_ADDRESS", "0.0.0.0:8080")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	err := viper.Unmarshal(&env)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}

	if err := validate.Struct(env); err != nil {
		log.Fatal(err)
	}
}

func main() {
	store := sessions.NewCookieStore([]byte(env.SESSION_SECRET))
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, env.ISSUER)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: env.CLIENT_ID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     env.CLIENT_ID,
		ClientSecret: env.CLIENT_SECRET,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  env.BASE_URL + env.AUTH_CALLBACK_PATH,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	r := mux.NewRouter()

	proxyUrl, err := url.Parse(env.BACKEND_URL)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyUrl)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")

		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		if token, ok := session.Values["id_token"].(string); ok {
			r.Host = env.BACKEND_URL
			r.URL.Host = env.BACKEND_URL
			r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
			proxy.ServeHTTP(w, r)
			return
		}

		state, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		nonce, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		setCookie(w, r, "state", state)
		setCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	r.HandleFunc(env.AUTH_CALLBACK_PATH, func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, err := store.Get(r, "session")
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		unsetCookie(w, r, "state")
		unsetCookie(w, r, "nonce")

		session.Values["id_token"] = rawIDToken
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	http.ListenAndServe(env.BIND_ADDRESS, r)
}
