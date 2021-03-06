package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	_ "github.com/lib/pq"
	"github.com/pardot/deci/oidcserver"
	"github.com/pardot/deci/signer"
	"github.com/pardot/deci/storage"
	"github.com/pardot/deci/storage/memory"
	sqlstor "github.com/pardot/deci/storage/sql"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/alecthomas/kingpin.v2"
	jose "gopkg.in/square/go-jose.v2"
)

func main() {
	ctx := context.Background()

	var (
		issuer = kingpin.Flag("issuer", "Issuer URL to serve as").Default("http://localhost:5556").URL()
		dbURL  = kingpin.Flag("db", "URL to Postgres database, e.g postgres://localhost/deci_dev?sslmode=disable. If empty, in-memory is used.").String()
		listen = kingpin.Flag("listen", "Addr to listen on").Default("127.0.0.1:5556").String()
		debug  = kingpin.Flag("debug", "debug log level").Default("true").Bool()

		// OIDC connector options (optional)
		oidcIssuer       = kingpin.Flag("oidc-issuer", "Upstream OIDC issuer URL").URL()
		oidcClientID     = kingpin.Flag("oidc-client-id", "OIDC Client ID").String()
		oidcClientSecret = kingpin.Flag("oidc-client-secret", "OIDC Client Secret").String()

		skipConsent = kingpin.Flag("skip-consent", "Skip the consent screeen").Default("false").Bool()

		csrfKey = kingpin.Flag("csrf-key", "32 byte key for CSRF protection, hex format").Default("0000000000000000000000000000000000000000000000000000000000000000").String()
	)
	kingpin.Parse()

	l := logrus.New()
	if *debug {
		l.SetLevel(logrus.DebugLevel)
	}

	var stor storage.Storage
	if *dbURL != "" {
		db, err := sql.Open("postgres", *dbURL)
		if err != nil {
			l.WithError(err).Fatal("Failed to open SQL connection")
		}

		stor, err = sqlstor.New(ctx, db)
		if err != nil {
			l.WithError(err).Fatal("Failed to initialize storage")
		}
	} else {
		stor = memory.New()
	}

	privs, pubs := mustGenKeyset(2)
	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: privs.Keys[0]}
	signer := signer.NewStatic(signingKey, pubs.Keys)

	clients := oidcserver.NewStaticClientSource([]*oidcserver.Client{
		{
			ID:           "example-app",
			Secret:       "ZXhhbXBsZS1hcHAtc2VjcmV0",
			RedirectURIs: []string{"http://127.0.0.1:5555/callback"},
		},
		{
			ID:     "openid-certification",
			Secret: "openid-certification",
			RedirectURIs: []string{
				"https://op.certification.openid.net:61944/authz_cb",
				"https://op.certification.openid.net:61944/authz_post",
			},
		},
	})

	mux := http.NewServeMux()

	connectors := map[string]oidcserver.Connector{
		"static": &staticIdentityConnector{
			identity: oidcserver.Identity{
				UserID:        "jdoe",
				Username:      "jdoe",
				Email:         "jdoe@example.com",
				EmailVerified: true,
				Groups:        []string{"group"},
			},
		},
	}

	if *oidcIssuer != nil {
		log.Printf("Using upstream issuer: %s", (*oidcIssuer).String())
		provider, err := oidc.NewProvider(ctx, (*oidcIssuer).String())
		if err != nil {
			l.WithError(err).Fatal("Failed to construct OIDC provider")
		}

		oauth2Config := &oauth2.Config{
			ClientID:     *oidcClientID,
			ClientSecret: *oidcClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  (*issuer).String() + "/oidc/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

		connector := &oidcConnector{
			provider:     provider,
			oauth2Config: oauth2Config,
		}
		connectors["oidc"] = connector

		mux.Handle((*issuer).Path+"/oidc/", http.StripPrefix((*issuer).Path+"/oidc", connector))
	}

	var server http.Handler
	var err error

	binaryCSRFKey, err := hex.DecodeString(*csrfKey)
	if err != nil {
		l.WithError(err).Fatalf("Failed to hex decode CSRF key")
	} else if len(binaryCSRFKey) != 32 {
		l.Fatal("CSRF key must be 32-bytes, hex encoded")
	}

	server, err = oidcserver.New((*issuer).String(), stor, signer, connectors, clients,
		oidcserver.WithLogger(l), oidcserver.WithSkipApprovalScreen(*skipConsent))
	if err != nil {
		l.WithError(err).Fatal("Failed to construct server")
	}
	mux.Handle((*issuer).Path+"/", http.StripPrefix((*issuer).Path, server))

	l.Infof("Listening on %s", *listen)
	l.WithError(http.ListenAndServe(*listen, mux)).Fatal()
}

type staticIdentityConnector struct {
	identity      oidcserver.Identity
	authenticator oidcserver.Authenticator
}

func (s *staticIdentityConnector) Initialize(authenticator oidcserver.Authenticator) {
	s.authenticator = authenticator
}

// LoginPage just automatically approves the connection and finalizes the flow
func (s *staticIdentityConnector) LoginPage(w http.ResponseWriter, r *http.Request, lr oidcserver.LoginRequest) {
	// just auto mark the session as good, and redirect the user to the final page
	ret, err := s.authenticator.Authenticate(r.Context(), lr.AuthID, s.identity)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal error: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

// Refresh updates the identity during a refresh token request.
func (s *staticIdentityConnector) Refresh(_ context.Context, _ oidcserver.Scopes, _ oidcserver.Identity) (oidcserver.Identity, error) { // nolint:unparam // err is nil, but interface req'd
	return s.identity, nil
}

type oidcConnector struct {
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	authenticator oidcserver.Authenticator
}

func (c *oidcConnector) Initialize(authenticator oidcserver.Authenticator) {
	c.authenticator = authenticator
}

func (c *oidcConnector) LoginPage(w http.ResponseWriter, r *http.Request, lr oidcserver.LoginRequest) {
	http.Redirect(w, r, c.oauth2Config.AuthCodeURL(lr.AuthID), http.StatusSeeOther)
}

func (c *oidcConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate this is /callback

	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		http.Error(w, q.Get("error_description"), http.StatusForbidden)
		return
	}

	state := q.Get("state")
	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	verifier := c.provider.Verifier(&oidc.Config{ClientID: c.oauth2Config.ClientID})
	_, err = verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}

	ui, err := c.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to fetch userinfo: %v", err), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Name string `json:"name"`
	}

	if err := ui.Claims(&claims); err != nil {
		http.Error(w, fmt.Sprintf("failed to extract claims from userinfo: %v", err), http.StatusInternalServerError)
		return
	}

	identity := oidcserver.Identity{
		UserID:        ui.Subject,
		Username:      claims.Name,
		Email:         ui.Email,
		EmailVerified: ui.EmailVerified,
	}

	url, err := c.authenticator.Authenticate(r.Context(), state, identity)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to finalize identity: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, url, http.StatusSeeOther)
}

// mustGenKeyset returns a set of public and private keys, with numKeys in each.
func mustGenKeyset(numKeys int) (privs *jose.JSONWebKeySet, pubs *jose.JSONWebKeySet) {
	const (
		alg = jose.RS256
		use = "sig"
	)

	privs, pubs = new(jose.JSONWebKeySet), new(jose.JSONWebKeySet)
	for i := 0; i < numKeys; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		b := make([]byte, 5)
		_, err = rand.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		kid := base32.StdEncoding.EncodeToString(b)
		priv := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: use}
		pub := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: string(alg), Use: use}
		if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
			panic("invalid keys were generated")
		}
		privs.Keys = append(privs.Keys, priv)
		pubs.Keys = append(pubs.Keys, pub)
	}
	return privs, pubs
}
