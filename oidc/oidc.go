// package oidc contains a OIDC binding for authorization.
package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
)

// Credentials stores generic oauth creds
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

var (
	conf        *oauth2.Config
	credentials Credentials
	state       string
	store       sessions.CookieStore
	issuer      string
	claims      struct{}
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func Setup(redirectURL, oidcIssuer string, cred *Credentials, scopes []string, secret []byte, oAuthClaims struct{}) {
	store = sessions.NewCookieStore(secret)
	cred = cred
	issuer = oidcIssuer
	claims = oAuthClaims
	conf = &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		Scopes:       append([]string{oidc.ScopeOpenID}, scopes...),
	}
}

func Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}

func LoginHandler(ctx *gin.Context) {
	state = randToken()
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Save()
	ctx.Writer.Write([]byte("<html><title>Golang OIDC</title> <body> <a href='" + GetLoginURL(state) + "'><button>Login with OIDC!</button> </a> </body></html>"))
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Initialize OIDC provider
		provider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Could not create OIDC provider: %s", err))
			return
		}
		// Adjust config with updated endpoint
		conf.Endpoint = provider.Endpoint()

		// Handle the exchange code to initiate a transport.
		session := sessions.Default(ctx)
		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		oauth2Token, err := conf.Exchange(ctx, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to exchange OAuth Token: %s", err))
			return
		}

		rawToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to get raw OAuth token: %s", err))
			return
		}

		idToken, err := provider.Verifier(&oidc.Config{ClientID: conf.ClientID}).Verify(ctx, rawToken)
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to validate token: %s", err))
			return
		}

		if err := idToken.Claims(&claims); err != nil {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Failed to get claims: %s", err))
			return
		}

		// save userinfo, which could be used in Handlers
		ctx.Set("user", claims)
	}
}
