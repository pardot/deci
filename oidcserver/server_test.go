package oidcserver

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/kylelemons/godebug/pretty"
	"github.com/pardot/deci/signer"
	"github.com/pardot/deci/storage/disk"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	jose "gopkg.in/square/go-jose.v2"
)

func mustLoad(s string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("no pem data found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

var testKey = mustLoad(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArmoiX5G36MKPiVGS1sicruEaGRrbhPbIKOf97aGGQRjXVngo
Knwd2L4T9CRyABgQm3tLHHcT5crODoy46wX2g9onTZWViWWuhJ5wxXNmUbCAPWHb
j9SunW53WuLYZ/IJLNZt5XYCAFPjAakWp8uMuuDwWo5EyFaw85X3FSMhVmmaYDd0
cn+1H4+NS/52wX7tWmyvGUNJ8lzjFAnnOtBJByvkyIC7HDphkLQV4j//sMNY1mPX
HbsYgFv2J/LIJtkjdYO2UoDhZG3Gvj16fMy2JE2owA8IX4/s+XAmA2PiTfd0J5b4
drAKEcdDl83G6L3depEkTkfvp0ZLsh9xupAvIwIDAQABAoIBABKGgWonPyKA7+AF
AxS/MC0/CZebC6/+ylnV8lm4K1tkuRKdJp8EmeL4pYPsDxPFepYZLWwzlbB1rxdK
iSWld36fwEb0WXLDkxrQ/Wdrj3Wjyqs6ZqjLTVS5dAH6UEQSKDlT+U5DD4lbX6RA
goCGFUeQNtdXfyTMWHU2+4yKM7NKzUpczFky+0d10Mg0ANj3/4IILdr3hqkmMSI9
1TB9ksWBXJxt3nGxAjzSFihQFUlc231cey/HhYbvAX5fN0xhLxOk88adDcdXE7br
3Ser1q6XaaFQSMj4oi1+h3RAT9MUjJ6johEqjw0PbEZtOqXvA1x5vfFdei6SqgKn
Am3BspkCgYEA2lIiKEkT/Je6ZH4Omhv9atbGoBdETAstL3FnNQjkyVau9f6bxQkl
4/sz985JpaiasORQBiTGY8JDT/hXjROkut91agi2Vafhr29L/mto7KZglfDsT4b2
9z/EZH8wHw7eYhvdoBbMbqNDSI8RrGa4mpLpuN+E0wsFTzSZEL+QMQUCgYEAzIQh
xnreQvDAhNradMqLmxRpayn1ORaPReD4/off+mi7hZRLKtP0iNgEVEWHJ6HEqqi1
r38XAc8ap/lfOVMar2MLyCFOhYspdHZ+TGLZfr8gg/Fzeq9IRGKYadmIKVwjMeyH
REPqg1tyrvMOE0HI5oqkko8JTDJ0OyVC0Vc6+AcCgYAqCzkywugLc/jcU35iZVOH
WLdFq1Vmw5w/D7rNdtoAgCYPj6nV5y4Z2o2mgl6ifXbU7BMRK9Hc8lNeOjg6HfdS
WahV9DmRA1SuIWPkKjE5qczd81i+9AHpmakrpWbSBF4FTNKAewOBpwVVGuBPcDTK
59IE3V7J+cxa9YkotYuCNQKBgCwGla7AbHBEm2z+H+DcaUktD7R+B8gOTzFfyLoi
Tdj+CsAquDO0BQQgXG43uWySql+CifoJhc5h4v8d853HggsXa0XdxaWB256yk2Wm
MePTCRDePVm/ufLetqiyp1kf+IOaw1Oyux0j5oA62mDS3Iikd+EE4Z+BjPvefY/L
E2qpAoGAZo5Wwwk7q8b1n9n/ACh4LpE+QgbFdlJxlfFLJCKstl37atzS8UewOSZj
FDWV28nTP9sqbtsmU8Tem2jzMvZ7C/Q0AuDoKELFUpux8shm8wfIhyaPnXUGZoAZ
Np4vUwMSYV5mopESLWOg3loBxKyLGFtgGKVCjGiQvy6zISQ4fQo=
-----END RSA PRIVATE KEY-----`)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

func newTestServer(_ context.Context, t *testing.T, updateServer func(s *Server)) (*httptest.Server, *Server) {
	t.Helper()

	var server *Server
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
	}))

	tmpdir, err := ioutil.TempDir("", "oidcserver-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	stor, err := disk.New(filepath.Join(tmpdir, "test.db"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: testKey}
	verificationKeys := []jose.JSONWebKey{
		{
			Key:       testKey.Public(),
			KeyID:     "testkey",
			Algorithm: "RS256",
			Use:       "sig",
		},
	}
	connectors := map[string]Connector{"mock": newMockConnector()}
	signer := signer.NewStatic(signingKey, verificationKeys)

	// make the updater into an option, so we can change the server a bit before
	// the constructor set up routes and the like.
	var usOpt ServerOption = func(svr *Server) error {
		if updateServer != nil {
			updateServer(svr)
			s.URL = svr.issuerURL.String()
			stor.Now = svr.now
		}
		return nil
	}

	server, err = New(s.URL, stor, signer, connectors, nil, WithLogger(logger), WithSkipApprovalScreen(true), usOpt)
	if err != nil {
		t.Fatal(err)
	}

	// update this, in case the updateServer changes the issuer
	// log.Printf("update url to %s", server.issuerURL.String())
	// s.URL = server.issuerURL.String()

	return s, server
}

func TestNewTestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newTestServer(ctx, t, nil)
}

func TestDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer, _ := newTestServer(ctx, t, nil)
	defer httpServer.Close()

	p, err := oidc.NewProvider(ctx, httpServer.URL)
	if err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	var got map[string]*json.RawMessage
	if err := p.Claims(&got); err != nil {
		t.Fatalf("failed to decode claims: %v", err)
	}

	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"userinfo_endpoint",
	}
	for _, field := range required {
		if _, ok := got[field]; !ok {
			t.Errorf("server discovery is missing required field %q", field)
		}
	}
}

// TestOAuth2CodeFlow runs integration tests against a test server. The tests stand up a server
// which requires no interaction to login, logs in through a test client, then passes the client
// and returned token to the test.
func TestOAuth2CodeFlow(t *testing.T) {
	clientID := "testclient"
	clientSecret := "testclientsecret"
	requestedScopes := []string{oidc.ScopeOpenID, "email", "profile", "groups", "offline_access"}

	t0 := time.Now()

	// Always have the time function used by the server return the same time so
	// we can predict expected values of "expires_in" fields exactly.
	now := func() time.Time { return t0 }

	// Used later when configuring test servers to set how long id_tokens will be valid for.
	//
	// The actual value of 30s is completely arbitrary. We just need to set a value
	// so tests can compute the expected "expires_in" field.
	idTokensValidFor := time.Second * 30

	// Connector used by the tests.
	var conn *mockConnector

	oidcConfig := &oidc.Config{SkipClientIDCheck: true}

	tests := []struct {
		name string
		// If specified these set of scopes will be used during the test case.
		scopes []string
		// if specified these acr_values will be used during the test case
		acrValues []string
		// handleToken provides the OAuth2 token response for the integration test.
		handleToken func(context.Context, *oidc.Provider, *oauth2.Config, *oauth2.Token) error
		// preAuthenticate can be used to hook into the connectors processing,
		// to check passed values and override returned.
		preAuthenticate func(t *testing.T, lr LoginRequest) Identity
	}{
		{
			name: "verify ID Token",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				idToken, ok := token.Extra("id_token").(string)
				if !ok {
					return fmt.Errorf("no id token found")
				}
				t.Logf("token: %s", idToken)
				if _, err := p.Verifier(oidcConfig).Verify(ctx, idToken); err != nil {
					return fmt.Errorf("failed to verify id token: %v", err)
				}
				return nil
			},
		},
		{
			name: "fetch userinfo",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				ui, err := p.UserInfo(ctx, config.TokenSource(ctx, token))
				if err != nil {
					return fmt.Errorf("failed to fetch userinfo: %v", err)
				}
				if conn.authFunc(LoginRequest{}).Email != ui.Email {
					return fmt.Errorf("expected email to be %v, got %v", conn.authFunc(LoginRequest{}).Email, ui.Email)
				}
				return nil
			},
		},
		{
			name: "verify id token and oauth2 token expiry",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				expectedExpiry := now().Add(idTokensValidFor)

				timeEq := func(t1, t2 time.Time, within time.Duration) bool {
					return t1.Sub(t2) < within
				}

				if !timeEq(token.Expiry, expectedExpiry, time.Second) {
					return fmt.Errorf("expected expired_in to be %s, got %s", expectedExpiry, token.Expiry)
				}

				rawIDToken, ok := token.Extra("id_token").(string)
				if !ok {
					return fmt.Errorf("no id token found")
				}
				idToken, err := p.Verifier(oidcConfig).Verify(ctx, rawIDToken)
				if err != nil {
					return fmt.Errorf("failed to verify id token: %v", err)
				}
				if !timeEq(idToken.Expiry, expectedExpiry, time.Second) {
					return fmt.Errorf("expected id token expiry to be %s, got %s", expectedExpiry, token.Expiry)
				}
				return nil
			},
		},
		{
			name: "verify at_hash",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				rawIDToken, ok := token.Extra("id_token").(string)
				if !ok {
					return fmt.Errorf("no id token found")
				}
				idToken, err := p.Verifier(oidcConfig).Verify(ctx, rawIDToken)
				if err != nil {
					return fmt.Errorf("failed to verify id token: %v", err)
				}

				var claims struct {
					AtHash string `json:"at_hash"`
				}
				if err := idToken.Claims(&claims); err != nil {
					return fmt.Errorf("failed to decode raw claims: %v", err)
				}
				if claims.AtHash == "" {
					return errors.New("no at_hash value in id_token")
				}
				wantAtHash, err := accessTokenHash(jose.RS256, token.AccessToken)
				if err != nil {
					return fmt.Errorf("computed expected at hash: %v", err)
				}
				if wantAtHash != claims.AtHash {
					return fmt.Errorf("expected at_hash=%q got=%q", wantAtHash, claims.AtHash)
				}

				return nil
			},
		},
		{
			name: "refresh token",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				// have to use time.Now because the OAuth2 package uses it.
				token.Expiry = time.Now().Add(time.Second * -10)
				if token.Valid() {
					return errors.New("token shouldn't be valid")
				}

				newToken, err := config.TokenSource(ctx, token).Token()
				if err != nil {
					return fmt.Errorf("failed to refresh token: %v", err)
				}
				if token.RefreshToken == newToken.RefreshToken {
					return fmt.Errorf("old refresh token was the same as the new token %q", token.RefreshToken)
				}

				if _, err := config.TokenSource(ctx, token).Token(); err == nil {
					return errors.New("was able to redeem the same refresh token twice")
				}
				return nil
			},
		},
		{
			name: "refresh with explicit scopes",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				v := url.Values{}
				v.Add("client_id", clientID)
				v.Add("client_secret", clientSecret)
				v.Add("grant_type", "refresh_token")
				v.Add("refresh_token", token.RefreshToken)
				v.Add("scope", strings.Join(requestedScopes, " "))
				resp, err := http.PostForm(p.Endpoint().TokenURL, v)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					dump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						panic(err)
					}
					return fmt.Errorf("unexpected response: %s", dump)
				}
				return nil
			},
		},
		{
			name: "refresh with extra spaces",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				v := url.Values{}
				v.Add("client_id", clientID)
				v.Add("client_secret", clientSecret)
				v.Add("grant_type", "refresh_token")
				v.Add("refresh_token", token.RefreshToken)

				// go-oidc adds an additional space before scopes when refreshing.
				// Since we support that client we choose to be more relaxed about
				// scope parsing, disregarding extra whitespace.
				v.Add("scope", " "+strings.Join(requestedScopes, " "))
				resp, err := http.PostForm(p.Endpoint().TokenURL, v)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					dump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						panic(err)
					}
					return fmt.Errorf("unexpected response: %s", dump)
				}
				return nil
			},
		},
		{
			name:   "refresh with unauthorized scopes",
			scopes: []string{"openid", "email"},
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				v := url.Values{}
				v.Add("client_id", clientID)
				v.Add("client_secret", clientSecret)
				v.Add("grant_type", "refresh_token")
				v.Add("refresh_token", token.RefreshToken)
				// Request a scope that wasn't requestd initially.
				v.Add("scope", "oidc email profile")
				resp, err := http.PostForm(p.Endpoint().TokenURL, v)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					dump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						panic(err)
					}
					return fmt.Errorf("unexpected response: %s", dump)
				}
				return nil
			},
		},
		{
			// This test ensures that the connector.RefreshConnector interface is being
			// used when clients request a refresh token.
			name: "refresh with identity changes",
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				// have to use time.Now because the OAuth2 package uses it.
				token.Expiry = time.Now().Add(time.Second * -10)
				if token.Valid() {
					return errors.New("token shouldn't be valid")
				}

				ident := Identity{
					UserID:        "fooid",
					Username:      "foo",
					Email:         "foo@bar.com",
					EmailVerified: true,
					Groups:        []string{"foo", "bar"},
				}
				conn.refreshFunc = func(_ Identity) Identity {
					return ident
				}

				type claims struct {
					Username      string   `json:"name"`
					Email         string   `json:"email"`
					EmailVerified bool     `json:"email_verified"`
					Groups        []string `json:"groups"`
				}
				want := claims{ident.Username, ident.Email, ident.EmailVerified, ident.Groups}

				newToken, err := config.TokenSource(ctx, token).Token()
				if err != nil {
					return fmt.Errorf("failed to refresh token: %v", err)
				}
				rawIDToken, ok := newToken.Extra("id_token").(string)
				if !ok {
					return fmt.Errorf("no id_token in refreshed token")
				}
				idToken, err := p.Verifier(oidcConfig).Verify(ctx, rawIDToken)
				if err != nil {
					return fmt.Errorf("failed to verify id token: %v", err)
				}
				var got claims
				if err := idToken.Claims(&got); err != nil {
					return fmt.Errorf("failed to unmarshal claims: %v", err)
				}

				if diff := pretty.Compare(want, got); diff != "" {
					return fmt.Errorf("got identity != want identity: %s", diff)
				}
				return nil
			},
		},
		{
			name:      "Connector that handles acr_values",
			acrValues: []string{"phrh", "phr"},
			preAuthenticate: func(t *testing.T, lr LoginRequest) Identity {
				if len(lr.ACRValues) != 2 {
					t.Errorf("want: 2 acr values got: %d", len(lr.ACRValues))
					return Identity{}
				}
				val0 := lr.ACRValues[0]
				return Identity{
					UserID: "test",
					ACR:    &val0,
					AMR:    []string{"mfa"},
				}
			},
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				type claims struct {
					ACR string   `json:"acr"`
					AMR []string `json:"amr"`
				}
				want := claims{"phrh", []string{"mfa"}}

				rawIDToken, ok := token.Extra("id_token").(string)
				if !ok {
					return fmt.Errorf("no id token found")
				}
				t.Logf("token: %s", rawIDToken)
				idToken, err := p.Verifier(oidcConfig).Verify(ctx, rawIDToken)
				if err != nil {
					return fmt.Errorf("failed to verify id token: %v", err)
				}

				var got claims
				if err := idToken.Claims(&got); err != nil {
					return fmt.Errorf("failed to unmarshal claims: %v", err)
				}

				if diff := pretty.Compare(want, got); diff != "" {
					return fmt.Errorf("got identity != want identity: %s", diff)
				}
				return nil
			},
		},
		{
			name:      "Connector that ignores acr_values",
			acrValues: []string{"phrh", "phr"},
			handleToken: func(ctx context.Context, p *oidc.Provider, config *oauth2.Config, token *oauth2.Token) error {
				type claims struct {
					ACR *string `json:"acr,omitempty"`
				}

				rawIDToken, ok := token.Extra("id_token").(string)
				if !ok {
					return fmt.Errorf("no id token found")
				}
				t.Logf("token: %s", rawIDToken)
				idToken, err := p.Verifier(oidcConfig).Verify(ctx, rawIDToken)
				if err != nil {
					return fmt.Errorf("failed to verify id token: %v", err)
				}

				var got claims
				if err := idToken.Claims(&got); err != nil {
					return fmt.Errorf("failed to unmarshal claims: %v", err)
				}

				if got.ACR != nil {
					t.Errorf("want: acr not passed through, got: %s", *got.ACR)
				}

				return nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Setup a dex server.
			httpServer, s := newTestServer(ctx, t, func(s *Server) {
				s.now = now
				s.idTokensValidFor = idTokensValidFor
			})
			defer httpServer.Close()

			mockConn := s.connectors["mock"]
			conn = mockConn.(*mockConnector)
			if tc.preAuthenticate != nil {
				conn.authFunc = func(lr LoginRequest) Identity {
					t.Log("preauth called")
					ident := tc.preAuthenticate(t, lr)
					t.Logf("returning %#v", ident)
					return ident
				}
			}

			// Query server's provider metadata.
			p, err := oidc.NewProvider(ctx, httpServer.URL)
			if err != nil {
				t.Fatalf("failed to get provider: %v", err)
			}

			var (
				// If the OAuth2 client didn't get a response, we need
				// to print the requests the user saw.
				gotCode           bool
				reqDump, respDump []byte // Auth step, not token.
				state             = "a_state"
			)
			defer func() {
				if !gotCode {
					t.Errorf("never got a code in callback\n%s\n%s", reqDump, respDump)
				}
			}()

			// Setup OAuth2 client.
			var oauth2Config *oauth2.Config
			oauth2Client := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var oa2Opts = []oauth2.AuthCodeOption{}
				if tc.acrValues != nil {
					oa2Opts = append(oa2Opts, oauth2.SetAuthURLParam("acr_values", strings.Join(tc.acrValues, " ")))
				}
				if r.URL.Path != "/callback" {
					// User is visiting app first time. Redirect to dex.
					http.Redirect(w, r, oauth2Config.AuthCodeURL(state, oa2Opts...), http.StatusSeeOther)
					return
				}

				// User is at '/callback' so they were just redirected _from_ dex.
				q := r.URL.Query()

				// Did dex return an error?
				if errType := q.Get("error"); errType != "" {
					if desc := q.Get("error_description"); desc != "" {
						t.Errorf("got error from server %s: %s", errType, desc)
					} else {
						t.Errorf("got error from server %s", errType)
					}
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				// Grab code, exchange for token.
				if code := q.Get("code"); code != "" {
					gotCode = true
					token, err := oauth2Config.Exchange(ctx, code)
					if err != nil {
						t.Errorf("failed to exchange code for token: %v", err)
						return
					}
					err = tc.handleToken(ctx, p, oauth2Config, token)
					if err != nil {
						t.Errorf("%s: %v", tc.name, err)
					}
					return
				}

				// Ensure state matches.
				if gotState := q.Get("state"); gotState != state {
					t.Errorf("state did not match, want=%q got=%q", state, gotState)
				}
				w.WriteHeader(http.StatusOK)
			}))

			defer oauth2Client.Close()

			// Regester the client above with dex.
			redirectURL := oauth2Client.URL + "/callback"
			client := Client{
				ID:           clientID,
				Secret:       clientSecret,
				RedirectURIs: []string{redirectURL},
			}
			s.clients = &simpleClientSource{
				Clients: map[string]*Client{
					clientID: &client,
				},
			}

			// Create the OAuth2 config.
			oauth2Config = &oauth2.Config{
				ClientID:     client.ID,
				ClientSecret: client.Secret,
				Endpoint:     p.Endpoint(),
				Scopes:       requestedScopes,
				RedirectURL:  redirectURL,
			}
			if len(tc.scopes) != 0 {
				oauth2Config.Scopes = tc.scopes
			}

			// Login!
			//
			//   1. First request to client, redirects to dex.
			//   2. Dex "logs in" the user, redirects to client with "code".
			//   3. Client exchanges "code" for "token" (id_token, refresh_token, etc.).
			//   4. Test is run with OAuth2 token response.
			//
			resp, err := http.Get(oauth2Client.URL + "/login")
			if err != nil {
				t.Fatalf("get failed: %v", err)
			}
			if reqDump, err = httputil.DumpRequest(resp.Request, false); err != nil {
				t.Fatal(err)
			}
			if respDump, err = httputil.DumpResponse(resp, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOAuth2ImplicitFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer, s := newTestServer(ctx, t, func(s *Server) {
		// Enable support for the implicit flow.
		s.supportedResponseTypes = map[string]bool{"code": true, "token": true, "id_token": true}
	})
	defer httpServer.Close()

	p, err := oidc.NewProvider(ctx, httpServer.URL)
	if err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	var (
		reqDump, respDump []byte
		gotIDToken        bool
		state             = "a_state"
		nonce             = "a_nonce"
	)
	defer func() {
		if !gotIDToken {
			t.Errorf("never got a id token in fragment\n%s\n%s", reqDump, respDump)
		}
	}()

	var oauth2Config *oauth2.Config
	oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback" {
			q := r.URL.Query()
			if errType := q.Get("error"); errType != "" {
				if desc := q.Get("error_description"); desc != "" {
					t.Errorf("got error from server %s: %s", errType, desc)
				} else {
					t.Errorf("got error from server %s", errType)
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// Fragment is checked by the client since net/http servers don't preserve URL fragments.
			// E.g.
			//
			//    r.URL.Fragment
			//
			// Will always be empty.
			w.WriteHeader(http.StatusOK)
			return
		}
		u := oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("response_type", "id_token token"), oidc.Nonce(nonce))
		http.Redirect(w, r, u, http.StatusSeeOther)
	}))

	defer oauth2Server.Close()

	redirectURL := oauth2Server.URL + "/callback"
	client := Client{
		ID:           "testclient",
		Secret:       "testclientsecret",
		RedirectURIs: []string{redirectURL},
	}
	s.clients = &simpleClientSource{
		Clients: map[string]*Client{
			client.ID: &client,
		},
	}

	idTokenVerifier := p.Verifier(&oidc.Config{
		ClientID: client.ID,
	})

	oauth2Config = &oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access"},
		RedirectURL:  redirectURL,
	}

	checkIDToken := func(u *url.URL) error {
		if u.Fragment == "" {
			return fmt.Errorf("url has no fragment: %s", u)
		}
		v, err := url.ParseQuery(u.Fragment)
		if err != nil {
			return fmt.Errorf("failed to parse fragment: %v", err)
		}
		rawIDToken := v.Get("id_token")
		if rawIDToken == "" {
			return errors.New("no id_token in fragment")
		}
		idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			return fmt.Errorf("failed to verify id_token: %v", err)
		}
		if idToken.Nonce != nonce {
			return fmt.Errorf("failed to verify id_token: nonce was %v, but want %v", idToken.Nonce, nonce)
		}
		return nil
	}

	httpClient := &http.Client{
		// net/http servers don't preserve URL fragments when passing the request to
		// handlers. The only way to get at that values is to check the redirect on
		// the client side.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return errors.New("too many redirects")
			}

			// If we're being redirected back to the client server, inspect the URL fragment
			// for an ID Token.
			u := req.URL.String()
			if strings.HasPrefix(u, oauth2Server.URL) {
				if err := checkIDToken(req.URL); err == nil {
					gotIDToken = true
				} else {
					t.Error(err)
				}
			}
			return nil
		},
	}

	resp, err := httpClient.Get(oauth2Server.URL + "/login")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if reqDump, err = httputil.DumpRequest(resp.Request, false); err != nil {
		t.Fatal(err)
	}
	if respDump, err = httputil.DumpResponse(resp, true); err != nil {
		t.Fatal(err)
	}
}

func TestCrossClientScopes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer, s := newTestServer(ctx, t, nil)
	defer httpServer.Close()

	p, err := oidc.NewProvider(ctx, httpServer.URL)
	if err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	var (
		reqDump, respDump []byte
		gotCode           bool
		state             = "a_state"
	)
	defer func() {
		if !gotCode {
			t.Errorf("never got a code in callback\n%s\n%s", reqDump, respDump)
		}
	}()

	testClientID := "testclient"
	peerID := "peer"

	var oauth2Config *oauth2.Config
	oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback" {
			q := r.URL.Query()
			if errType := q.Get("error"); errType != "" {
				if desc := q.Get("error_description"); desc != "" {
					t.Errorf("got error from server %s: %s", errType, desc)
				} else {
					t.Errorf("got error from server %s", errType)
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if code := q.Get("code"); code != "" {
				gotCode = true
				token, err := oauth2Config.Exchange(ctx, code)
				if err != nil {
					t.Errorf("failed to exchange code for token: %v", err)
					return
				}
				rawIDToken, ok := token.Extra("id_token").(string)
				if !ok {
					t.Errorf("no id token found: %v", err)
					return
				}
				idToken, err := p.Verifier(&oidc.Config{ClientID: testClientID}).Verify(ctx, rawIDToken)
				if err != nil {
					t.Errorf("failed to parse ID Token: %v", err)
					return
				}

				sort.Strings(idToken.Audience)
				expAudience := []string{peerID, testClientID}
				if !reflect.DeepEqual(idToken.Audience, expAudience) {
					t.Errorf("expected audience %q, got %q", expAudience, idToken.Audience)
				}

			}
			if gotState := q.Get("state"); gotState != state {
				t.Errorf("state did not match, want=%q got=%q", state, gotState)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusSeeOther)
	}))

	defer oauth2Server.Close()

	redirectURL := oauth2Server.URL + "/callback"
	client := Client{
		ID:           testClientID,
		Secret:       "testclientsecret",
		RedirectURIs: []string{redirectURL},
	}
	scs := &simpleClientSource{
		Clients: map[string]*Client{
			client.ID: &client,
		},
	}

	peer := Client{
		ID:           peerID,
		Secret:       "foobar",
		TrustedPeers: []string{"testclient"},
	}
	scs.Clients[peer.ID] = &peer

	s.clients = scs

	oauth2Config = &oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint:     p.Endpoint(),
		Scopes: []string{
			oidc.ScopeOpenID, "profile", "email",
			"audience:server:client_id:" + client.ID,
			"audience:server:client_id:" + peer.ID,
		},
		RedirectURL: redirectURL,
	}

	resp, err := http.Get(oauth2Server.URL + "/login")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if reqDump, err = httputil.DumpRequest(resp.Request, false); err != nil {
		t.Fatal(err)
	}
	if respDump, err = httputil.DumpResponse(resp, true); err != nil {
		t.Fatal(err)
	}
}

func TestCrossClientScopesWithAzpInAudienceByDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer, s := newTestServer(ctx, t, nil)
	defer httpServer.Close()

	p, err := oidc.NewProvider(ctx, httpServer.URL)
	if err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	var (
		reqDump, respDump []byte
		gotCode           bool
		state             = "a_state"
	)
	defer func() {
		if !gotCode {
			t.Errorf("never got a code in callback\n%s\n%s", reqDump, respDump)
		}
	}()

	testClientID := "testclient"
	peerID := "peer"

	var oauth2Config *oauth2.Config
	oauth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback" {
			q := r.URL.Query()
			if errType := q.Get("error"); errType != "" {
				if desc := q.Get("error_description"); desc != "" {
					t.Errorf("got error from server %s: %s", errType, desc)
				} else {
					t.Errorf("got error from server %s", errType)
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if code := q.Get("code"); code != "" {
				gotCode = true
				token, err := oauth2Config.Exchange(ctx, code)
				if err != nil {
					t.Errorf("failed to exchange code for token: %v", err)
					return
				}
				rawIDToken, ok := token.Extra("id_token").(string)
				if !ok {
					t.Errorf("no id token found: %v", err)
					return
				}
				idToken, err := p.Verifier(&oidc.Config{ClientID: testClientID}).Verify(ctx, rawIDToken)
				if err != nil {
					t.Errorf("failed to parse ID Token: %v", err)
					return
				}

				sort.Strings(idToken.Audience)
				expAudience := []string{peerID, testClientID}
				if !reflect.DeepEqual(idToken.Audience, expAudience) {
					t.Errorf("expected audience %q, got %q", expAudience, idToken.Audience)
				}

			}
			if gotState := q.Get("state"); gotState != state {
				t.Errorf("state did not match, want=%q got=%q", state, gotState)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusSeeOther)
	}))

	defer oauth2Server.Close()

	redirectURL := oauth2Server.URL + "/callback"
	client := Client{
		ID:           testClientID,
		Secret:       "testclientsecret",
		RedirectURIs: []string{redirectURL},
	}
	scs := &simpleClientSource{
		Clients: map[string]*Client{
			client.ID: &client,
		},
	}

	peer := Client{
		ID:           peerID,
		Secret:       "foobar",
		TrustedPeers: []string{"testclient"},
	}
	scs.Clients[peer.ID] = &peer

	s.clients = scs

	oauth2Config = &oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint:     p.Endpoint(),
		Scopes: []string{
			oidc.ScopeOpenID, "profile", "email",
			"audience:server:client_id:" + peer.ID,
		},
		RedirectURL: redirectURL,
	}

	resp, err := http.Get(oauth2Server.URL + "/login")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if reqDump, err = httputil.DumpRequest(resp.Request, false); err != nil {
		t.Fatal(err)
	}
	if respDump, err = httputil.DumpResponse(resp, true); err != nil {
		t.Fatal(err)
	}
}

type oauth2Client struct {
	config *oauth2.Config
	token  *oauth2.Token
	server *httptest.Server
}

// TestRefreshTokenFlow tests the refresh token code flow for oauth2. The test verifies
// that only valid refresh tokens can be used to refresh an expired token.
func TestRefreshTokenFlow(t *testing.T) {
	state := "state"
	now := func() time.Time { return time.Now() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServer, s := newTestServer(ctx, t, func(s *Server) {
		s.now = now
	})
	defer httpServer.Close()

	p, err := oidc.NewProvider(ctx, httpServer.URL)
	if err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	var oauth2Client oauth2Client

	oauth2Client.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			// User is visiting app first time. Redirect to dex.
			http.Redirect(w, r, oauth2Client.config.AuthCodeURL(state), http.StatusSeeOther)
			return
		}

		// User is at '/callback' so they were just redirected _from_ dex.
		q := r.URL.Query()

		if errType := q.Get("error"); errType != "" {
			if desc := q.Get("error_description"); desc != "" {
				t.Errorf("got error from server %s: %s", errType, desc)
			} else {
				t.Errorf("got error from server %s", errType)
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Grab code, exchange for token.
		if code := q.Get("code"); code != "" {
			token, err := oauth2Client.config.Exchange(ctx, code)
			if err != nil {
				t.Errorf("failed to exchange code for token: %v", err)
				return
			}
			oauth2Client.token = token
		}

		// Ensure state matches.
		if gotState := q.Get("state"); gotState != state {
			t.Errorf("state did not match, want=%q got=%q", state, gotState)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer oauth2Client.server.Close()

	// Register the client above with dex.
	redirectURL := oauth2Client.server.URL + "/callback"
	client := Client{
		ID:           "testclient",
		Secret:       "testclientsecret",
		RedirectURIs: []string{redirectURL},
	}
	s.clients = &simpleClientSource{
		Clients: map[string]*Client{
			client.ID: &client,
		},
	}

	oauth2Client.config = &oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "offline_access"},
		RedirectURL:  redirectURL,
	}

	if _, err = http.Get(oauth2Client.server.URL + "/login"); err != nil {
		t.Fatalf("get failed: %v", err)
	}

	tok := &oauth2.Token{
		RefreshToken: oauth2Client.token.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}

	// Login in again to receive a new token.
	if _, err = http.Get(oauth2Client.server.URL + "/login"); err != nil {
		t.Fatalf("get failed: %v", err)
	}

	// try to refresh expired token with old refresh token.
	newToken, err := oauth2Client.config.TokenSource(ctx, tok).Token()
	if err == nil {
		t.Errorf("Want: error when using expired refresh token, but none returned")
	}
	if newToken != nil {
		t.Errorf("Token refreshed with invalid refresh token.")
	}
}

type simpleClientSource struct {
	Clients map[string]*Client
}

func (s *simpleClientSource) GetClient(id string) (*Client, error) {
	if s.Clients == nil {
		return nil, errors.New("Clients not initialized")
	}
	c, ok := s.Clients[id]
	if !ok {
		return nil, fmt.Errorf("Client %q not found", id)
	}
	return c, nil
}
