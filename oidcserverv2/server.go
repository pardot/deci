package oidcserverv2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/gorilla/csrf"
	"github.com/pardot/deci/oidcserver"
	storagev1beta1 "github.com/pardot/deci/proto/deci/storage/v1beta1"
	storagev2beta1 "github.com/pardot/deci/proto/deci/storage/v2beta1"
	"github.com/pardot/deci/storage"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/sirupsen/logrus"
)

var _ oidcserver.Authenticator = (*Server)(nil)

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

// WithConsent injects a consent page to all oauth flows. A 32-byte CSRF key
// needs to be provided. if offlineOnly is true, this will only be applied to
// offline sessions
func WithConsent(csrfKey []byte, offlineOnly bool) ServerOption {
	return ServerOption(func(s *Server) error {
		s.consentAll = !offlineOnly
		s.consentOffline = offlineOnly
		if len(csrfKey) != 32 {
			return fmt.Errorf("CSRF key must be 32 bytes long")
		}
		csrfOpts := []csrf.Option{csrf.SameSite(csrf.SameSiteStrictMode)}
		if s.issuerURL.Scheme != "https" {
			csrfOpts = append(csrfOpts, csrf.Secure(false))
		}
		s.csrf = csrf.Protect([]byte(csrfKey), csrfOpts...)
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

	consentAll     bool
	consentOffline bool

	oidc *core.OIDC

	connector   oidcserver.Connector
	connectorID string

	clients *clientMgr

	sessionMgr *sessionMgr

	discovery *discovery.Handler

	issuerURL *url.URL

	mux      *http.ServeMux
	muxSetup sync.Once

	csrf func(http.Handler) http.Handler

	now func() time.Time
}

func New(issuer string, storage storage.Storage, signer oidcserver.Signer, connectors map[string]oidcserver.Connector, clients oidcserver.ClientSource, opts ...ServerOption) (*Server, error) {
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
		if s.consentAll || s.consentOffline {
			s.mux.Handle("/consent", s.csrf(http.HandlerFunc(s.consent)))
		}
		s.mux.Handle(
			"/.well-known/openid-configuration/",
			http.StripPrefix("/.well-known/openid-configuration", s.discovery),
		)
	})

	s.mux.ServeHTTP(w, req)
}

// Authenticate associates the user's identity with the given authID, then
// returns a URL the user should be redirected to. This will either be for
// a confirmation page, or the calling app
//
// This is passed to the connector and used via "Initialize"
func (s *Server) Authenticate(ctx context.Context, authID string, ident oidcserver.Identity) (returnURL string, err error) {
	l := s.logger.WithFields(logrus.Fields{
		"authID": authID,
		"userID": ident.UserID,
		"fn":     "Authenticate",
	})
	l.Info("Starting Authenticate")

	// Stash the data alongside our session

	sess := &storagev2beta1.Session{}
	sessVer, err := s.sessionMgr.storage.Get(ctx, sessKeyspace, authID, sess)
	if err != nil {
		return "", err
	}

	identToSess(ident, sess)

	if _, err := s.sessionMgr.storage.Put(ctx, sessKeyspace, authID, sessVer, sess); err != nil {
		l.WithError(err).Error("failed to put session")
		return "", err
	}

	if s.consentAll ||
		(s.consentOffline && strContains(sess.LoginRequest.Scopes, "offline_access")) {
		return fmt.Sprintf("/consent?authid=%s", authID), nil
	}
	return s.finishAuthenticate(ctx, authID)
}

func (s *Server) consent(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		s.finalizeConsent(w, req)
		return
	}
	s.renderConsent(w, req)
}

func (s *Server) renderConsent(w http.ResponseWriter, req *http.Request) {
	l := s.logger.WithField("fn", "renderConsent")
	ctx := req.Context()

	authID := req.URL.Query().Get("authid")
	if authID == "" {
		http.Error(w, "Missing auth ID", http.StatusBadRequest)
		return
	}

	sess := &storagev2beta1.Session{}
	if _, err := s.sessionMgr.storage.Get(ctx, sessKeyspace, authID, sess); err != nil {
		l.WithError(err).Error("failed to get session")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	cl, err := s.clients.clients.GetClient(sess.LoginRequest.ClientId)
	if err != nil {
		l.WithError(err).WithField("client-id", sess.LoginRequest.ClientId).Error("couldn't find client")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	cname := sess.LoginRequest.ClientId
	if cl.Name != "" {
		cname = cl.Name
	}

	td := &consentData{
		AuthID:     authID,
		ClientName: cname,
		Offline:    strContains(sess.LoginRequest.Scopes, "offline_access"),

		CSRFField: csrf.TemplateField(req),
	}

	if err := consentTmpl.Execute(w, td); err != nil {
		l.WithError(err).Error("failed to render template")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) finalizeConsent(w http.ResponseWriter, req *http.Request) {
	l := s.logger.WithField("fn", "renderConsent")
	ctx := req.Context()

	authID := req.Form.Get("authid")
	if authID == "" {
		http.Error(w, "Missing auth ID", http.StatusBadRequest)
		return
	}

	redir, err := s.finishAuthenticate(ctx, authID)
	if err != nil {
		l.WithError(err).Error("failed to finalize consent")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, redir, http.StatusFound)
}

// finishAuthenticate will finalize the authentication flow, and return the URL
// the user should be redirected to
func (s *Server) finishAuthenticate(ctx context.Context, authID string) (returnURL string, err error) {
	l := s.logger.WithFields(logrus.Fields{
		"authID": authID,
		"fn":     "finishAuthenticate",
	})
	l.Info("Starting")

	sess := &storagev2beta1.Session{}
	if _, err := s.sessionMgr.storage.Get(ctx, sessKeyspace, authID, sess); err != nil {
		l.WithError(err).Error("failed to get session")
		return "", err
	}

	ident := sessToIdentity(sess)

	var acr string
	if ident.ACR != nil {
		acr = *ident.ACR
	}

	auth := &core.Authorization{
		Scopes: sess.LoginRequest.Scopes,
		ACR:    acr,
		AMR:    ident.AMR,
	}

	l.WithFields(logrus.Fields{
		"scopes": auth.Scopes,
		"acr":    auth.ACR,
		"amr":    auth.AMR,
	}).Debug("finishing authorization")

	// upstream handles the redirecting, whereas we expect the URL.
	// capture the response and use that to create the URL.

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// we use the session ID as the auth ID
	if err := s.oidc.FinishAuthorization(w, req, authID, auth); err != nil {
		l.WithError(err).Error("error in OIDC FinishAuthorization call")
		return "", err
	}

	l.WithFields(logrus.Fields{
		"code":         w.Code,
		"location-set": w.Header().Get("location") != "",
	})
	l.Debug("called finish authorization")

	// TODO - better error checking?
	if w.Code != 302 {
		return "", fmt.Errorf("recorded unexpected response code from auth handler: %d", w.Code)
	}

	loc := w.Header().Get("location")
	if loc == "" {
		return "", fmt.Errorf("auth handler didn't set a location header")
	}

	l.Debug("Authentication successful, returning redirect")

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
	l := s.logger.WithFields(logrus.Fields{
		"fn": "authorization",
	})
	l.Debug("starting authorization")

	ar, err := s.oidc.StartAuthorization(w, req)
	if err != nil {
		l.WithError(err).Error("error starting authorization flow")
		return
	}

	l = l.WithFields(logrus.Fields{
		"sessionID": ar.SessionID,
		"clientID":  ar.ClientID,
	})
	l.Debug("authorization request parsed")

	if err := validateScopes(ar.Scopes); err != nil {
		l.WithError(err).Debug("request has unhandled scopes")
		// TODO - we should probably expose the auth error stuff in some way in pardot/oidc
		http.Error(w, "Unhandled scopes", http.StatusBadRequest)
		return
	}

	sess := &storagev2beta1.Session{}
	sessVer, err := s.sessionMgr.storage.Get(req.Context(), sessKeyspace, ar.SessionID, sess)
	if err != nil {
		l.WithError(err).Error("Failed getting session")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	sess.LoginRequest = &storagev2beta1.LoginRequest{
		Scopes:    ar.Scopes,
		AcrValues: ar.ACRValues,
		ClientId:  ar.ClientID,
	}

	if _, err := s.sessionMgr.storage.Put(req.Context(), sessKeyspace, ar.SessionID, sessVer, sess); err != nil {
		l.WithError(err).Error("error updating session")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	l.Debug("calling in to connector login page")

	s.connector.LoginPage(w, req, sessToLoginReq(ar.SessionID, sess))
}

func (s *Server) token(w http.ResponseWriter, req *http.Request) {
	l := s.logger.WithFields(logrus.Fields{
		"fn": "token",
	})
	l.Debug("calling OIDC token method")

	err := s.oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		l = l.WithField("sessionID", tr.SessionID)

		l.WithFields(logrus.Fields{
			"refreshable": tr.SessionRefreshable,
			"isrefresh":   tr.IsRefresh,
		})
		l.Debug("starting token callback")

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
			l.Debug("about to refresh with connector")
			newID, err := refconn.Refresh(req.Context(), sessToScopes(sess), sessToIdentity(sess))
			if err != nil {
				l.WithError(err).Debug("connector refresh returned error")
				// TODO - how can we make this more graceful if it's for auth
				// failed reasons.
				return nil, err
			}

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

		resp := &core.TokenResponse{
			IssueRefreshToken:      allowRefresh,
			IDToken:                idt,
			AccessTokenValidUntil:  s.now().Add(s.idTokensValidFor),
			RefreshTokenValidUntil: s.now().Add(s.refreshValidFor),
		}

		l.WithFields(logrus.Fields{
			"issueRefreshToken": resp.IssueRefreshToken,
			"accessTokValidTil": resp.AccessTokenValidUntil.String(),
			"refreshTokValid":   resp.RefreshTokenValidUntil.String(),
		})
		l.Debugf("returning token response: %#v", idt)

		return resp, nil
	})
	if err != nil {
		l.WithError(err).Error("Error in token endpoint")
	}
}

func (s *Server) userinfo(w http.ResponseWriter, req *http.Request) {
	l := s.logger.WithFields(logrus.Fields{
		"fn": "userinfo",
	})
	l.Debug("calling OIDC userinfo method")

	err := s.oidc.Userinfo(w, req, func(w io.Writer, uireq *core.UserinfoRequest) error {
		l = l.WithField("sessionID", uireq.SessionID)
		l.Debug("starting callback")

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
		l.WithError(err).Error("Error in userinfo endpoint")
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

const (
	scopeOpenID = "openid"

	// we just allow these anyway for now
	scopeProfile = "profile"
	scopeEmail   = "email"
	scopeAddress = "address"
	scopePhone   = "phone"

	scopeGroups = "groups"

	scopeOfflineAccess = "offline_access"

	// this is a dex thing we should support for now
	scopeFederatedID = "federated:id"
)

func validateScopes(scopes []string) error {
	var unhandled []string
	var openid bool

	for _, s := range scopes {
		switch s {
		case scopeOpenID:
			openid = true
		case scopeProfile, scopeEmail, scopeAddress, scopePhone, scopeGroups, scopeOfflineAccess, scopeFederatedID:
		default:
			unhandled = append(unhandled, s)
		}
	}
	if !openid {
		return fmt.Errorf("openid scope is required")
	}
	if len(unhandled) > 0 {
		return fmt.Errorf("unhandled scopes found: %v", unhandled)
	}
	return nil
}
