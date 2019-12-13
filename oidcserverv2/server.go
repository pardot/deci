package oidcserverv2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/pardot/deci/oidcserver"
	storagev1beta1 "github.com/pardot/deci/proto/deci/storage/v1beta1"
	storagev2beta1 "github.com/pardot/deci/proto/deci/storage/v2beta1"
	"github.com/pardot/deci/storage"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/sirupsen/logrus"
)

var _ oidcserver.Authenticator = (*Server)(nil)

type Signer oidcserver.Signer
type Connector oidcserver.Connector
type ClientSource oidcserver.ClientSource

// ServerOption defines optional configuration items for the OIDC server.
type ServerOption func(s *Server) error

// WithIDTokenValidity sets how long issued ID tokens are valid for
func WithIDTokenValidity(validFor time.Duration) ServerOption {
	return ServerOption(func(s *Server) error {
		s.idTokensValidFor = validFor
		return nil
	})
}

// WithAuthRequestValidity sets how long an authorization flow is considered
// valid.
func WithAuthRequestValidity(validFor time.Duration) ServerOption {
	return ServerOption(func(s *Server) error {
		s.authRequestsValidFor = validFor
		return nil
	})
}

// WithLogger sets a logger on the server, otherwise no output will be logged
func WithLogger(logger logrus.FieldLogger) ServerOption {
	return ServerOption(func(s *Server) error {
		s.logger = logger
		return nil
	})
}

// Server is a cut-down OIDC server. It is designed to be a drop-in for the
// current oidcserver as a migration step towards a pardot/oidc implementation
type Server struct {
	logger logrus.FieldLogger

	idTokensValidFor     time.Duration
	authRequestsValidFor time.Duration
	refreshValidFor      time.Duration

	oidc *core.OIDC

	connector   Connector
	connectorID string

	clients *clientMgr

	sessionMgr *sessionMgr

	discovery *discovery.Handler

	issuerURL *url.URL

	mux      *http.ServeMux
	muxSetup sync.Once

	now func() time.Time
}

func New(issuer string, storage storage.Storage, signer Signer, connectors map[string]Connector, clients ClientSource, opts ...ServerOption) (*Server, error) {
	issURL, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}

	if len(connectors) != 1 {
		return nil, fmt.Errorf("only one connector is currently supported")
	}

	smgr := &sessionMgr{storage: storage}
	cmgr := &clientMgr{clients: clients}

	md := &discovery.ProviderMetadata{
		Issuer:                issURL.String(),
		AuthorizationEndpoint: issURL.String() + "/auth",
		TokenEndpoint:         issURL.String() + "/token",
		UserinfoEndpoint:      issURL.String() + "/userinfo",
	}

	disco, err := discovery.NewHandler(md,
		discovery.WithCoreDefaults(),
		discovery.WithKeysource(signer, 5*time.Second),
	)
	if err != nil {
		return nil, err
	}

	logger := logrus.New()
	logger.Out = ioutil.Discard

	s := &Server{
		idTokensValidFor:     15 * time.Minute,
		authRequestsValidFor: 15 * time.Minute,
		refreshValidFor:      12 * time.Hour,

		issuerURL:  issURL,
		logger:     logger,
		now:        time.Now,
		clients:    cmgr,
		sessionMgr: smgr,
		discovery:  disco,
	}

	for k, v := range connectors {
		s.connectorID = k
		s.connector = v
		v.Initialize(s)
	}

	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}

	ccfg := &core.Config{
		AuthValidityTime: s.authRequestsValidFor,
	}

	o, err := core.New(ccfg, smgr, cmgr, signer)
	if err != nil {
		return nil, err
	}

	s.oidc = o

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.muxSetup.Do(func() {
		s.mux = http.NewServeMux()
		s.mux.HandleFunc("/auth", s.authorization)
		s.mux.HandleFunc("/token", s.token)
		s.mux.HandleFunc("/userinfo", s.userinfo)
		s.mux.Handle(
			"/.well-known/openid-configuration/",
			http.StripPrefix("/.well-known/openid-configuration", s.discovery),
		)
	})

	s.mux.ServeHTTP(w, req)
}

// Authenticate associates the user's identity with the given authID, then
// returns final redirect URL.
//
// This is passed to the connector and used via "Initialize"
func (s *Server) Authenticate(ctx context.Context, authID string, ident oidcserver.Identity) (returnURL string, err error) {
	var acr string
	if ident.ACR != nil {
		acr = *ident.ACR
	}

	// Stash the data alongside our session

	sess := &storagev2beta1.Session{}
	sessVer, err := s.sessionMgr.storage.Get(ctx, sessKeyspace, authID, sess)
	if err != nil {
		return "", err
	}

	identToSess(ident, sess)

	log.Printf("storing sess AMR: %v", sess.Claims.Amr)

	if _, err := s.sessionMgr.storage.Put(ctx, sessKeyspace, authID, sessVer, sess); err != nil {
		return "", err
	}

	auth := &core.Authorization{
		Scopes: sess.LoginRequest.Scopes,
		ACR:    acr,
		AMR:    ident.AMR,
	}

	// upstream handles the redirecting, whereas we expect the URL.
	// capture the response and use that to create the URL.

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// we use the session ID as the auth ID
	if err := s.oidc.FinishAuthorization(w, req, authID, auth); err != nil {
		return "", err
	}

	// TODO - better error checking?
	if w.Code != 302 {
		return "", fmt.Errorf("recorded unexpected response code from auth handler: %d", w.Code)
	}

	loc := w.Header().Get("location")
	if loc == "" {
		return "", fmt.Errorf("auth handler didn't set a location header")
	}

	return loc, nil
}

// LoginRequest loads the login request information for a given authID.
func (s *Server) LoginRequest(ctx context.Context, authID string) (oidcserver.LoginRequest, error) {
	sess := &storagev2beta1.Session{}
	_, err := s.sessionMgr.storage.Get(ctx, sessKeyspace, authID, sess)
	if err != nil {
		return oidcserver.LoginRequest{}, err
	}

	return sessToLoginReq(authID, sess), nil
}

// authorization is called at the start of the flow
func (s *Server) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidc.StartAuthorization(w, req)
	if err != nil {
		s.logger.WithError(err).Error("error starting authorization flow")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// TODO - Validate the scopes provided, ensuring only the ones we'd handle are present
	sess := &storagev2beta1.Session{}
	sessVer, err := s.sessionMgr.storage.Get(req.Context(), sessKeyspace, ar.SessionID, sess)
	if err != nil {
		s.logger.WithError(err).Error("Failed getting session")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	sess.LoginRequest = &storagev2beta1.LoginRequest{
		Scopes:    ar.Scopes,
		AcrValues: ar.ACRValues,
	}

	if _, err := s.sessionMgr.storage.Put(req.Context(), sessKeyspace, ar.SessionID, sessVer, sess); err != nil {
		s.logger.WithError(err).Error("error updating session")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.connector.LoginPage(w, req, sessToLoginReq(ar.SessionID, sess))
}

func (s *Server) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		sess := &storagev2beta1.Session{}
		sessVer, err := s.sessionMgr.storage.Get(req.Context(), sessKeyspace, tr.SessionID, sess)
		if err != nil {
			return nil, err
		}

		// check if this is a refresh or not. if so, hit the callback connector
		// piece

		refconn, ok := s.connector.(oidcserver.RefreshConnector)

		allowRefresh := ok && tr.SessionRefreshable

		if ok && tr.IsRefresh {
			newID, err := refconn.Refresh(req.Context(), sessToScopes(sess), sessToIdentity(sess))
			if err != nil {
				// TODO - how can we make this more graceful if it's for auth
				// failed reasons.
				return nil, err
			}

			log.Printf("refresh req newID: %v", newID)

			identToSess(newID, sess)

			_, err = s.sessionMgr.storage.Put(req.Context(), sessKeyspace, tr.SessionID, sessVer, sess)
			if err != nil {
				return nil, err
			}
		}

		// claims2tok fills the subject
		idt := tr.PrefillIDToken(s.issuerURL.String(), "", s.now().Add(s.idTokensValidFor))

		idt, err = s.claims2token(sess.Claims, idt)
		if err != nil {
			return nil, err
		}

		return &core.TokenResponse{
			IssueRefreshToken:      allowRefresh,
			IDToken:                idt,
			AccessTokenValidUntil:  s.now().Add(s.idTokensValidFor),
			RefreshTokenValidUntil: s.now().Add(s.refreshValidFor),
		}, nil
	})
	if err != nil {
		s.logger.WithError(err).Error("Error in token endpoint")
	}
}

func (s *Server) userinfo(w http.ResponseWriter, req *http.Request) {
	err := s.oidc.Userinfo(w, req, func(w io.Writer, uireq *core.UserinfoRequest) error {
		sess := &storagev2beta1.Session{}
		_, err := s.sessionMgr.storage.Get(req.Context(), sessKeyspace, uireq.SessionID, sess)
		if err != nil {
			return err
		}

		tok, err := s.claims2token(sess.Claims, core.IDToken{})
		if err != nil {
			return err
		}

		if err := json.NewEncoder(w).Encode(tok); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		s.logger.WithError(err).Error("Error in userinfo endpoint")
	}
}

func strContains(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

func sessToLoginReq(sessID string, sess *storagev2beta1.Session) oidcserver.LoginRequest {
	return oidcserver.LoginRequest{
		AuthID:    sessID,
		Scopes:    sessToScopes(sess),
		ACRValues: sess.LoginRequest.AcrValues,
	}
}

func sessToScopes(sess *storagev2beta1.Session) oidcserver.Scopes {
	return oidcserver.Scopes{
		OfflineAccess: strContains(sess.LoginRequest.Scopes, "offline_access"),
		Groups:        strContains(sess.LoginRequest.Scopes, "groups"),
	}
}

func sessToIdentity(sess *storagev2beta1.Session) oidcserver.Identity {
	i := oidcserver.Identity{
		UserID:        sess.Claims.UserId,
		Username:      sess.Claims.Username,
		Email:         sess.Claims.Email,
		EmailVerified: sess.Claims.EmailVerified,
		Groups:        sess.Claims.Groups,
		AMR:           sess.Claims.Amr,
		ConnectorData: sess.ConnectorData,
	}
	if sess.Claims.Acr != nil {
		v := sess.Claims.Acr.Value
		i.ACR = &v
	}
	return i
}

func identToSess(ident oidcserver.Identity, sess *storagev2beta1.Session) {
	claims := &storagev1beta1.Claims{
		UserId:        ident.UserID,
		Username:      ident.Username,
		Email:         ident.Email,
		EmailVerified: ident.EmailVerified,
		Groups:        ident.Groups,
		Amr:           ident.AMR,
	}
	if ident.ACR != nil {
		claims.Acr = &wrappers.StringValue{Value: *ident.ACR}
	}

	sess.Claims = claims
	sess.ConnectorData = ident.ConnectorData
}

func (s *Server) claims2token(claims *storagev1beta1.Claims, tok core.IDToken) (core.IDToken, error) {
	if tok.Extra == nil {
		tok.Extra = map[string]interface{}{}
	}

	submsg := &storagev2beta1.DexSubject{
		UserId: claims.UserId,
		ConnId: s.connectorID,
	}
	subpb, err := proto.Marshal(submsg)
	if err != nil {
		return core.IDToken{}, err
	}
	tok.Subject = base64.RawURLEncoding.EncodeToString(subpb)

	tok.AMR = claims.Amr
	tok.Extra["email_verified"] = claims.EmailVerified

	if len(claims.Groups) > 0 {
		tok.Extra["groups"] = claims.Groups
	}
	if claims.Username != "" {
		tok.Extra["name"] = claims.Username
	}
	if claims.Email != "" {
		tok.Extra["email"] = claims.Email
	}
	if claims.Acr != nil {
		tok.ACR = claims.Acr.Value
	}

	return tok, nil
}
