package oidcserver

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pardot/deci/oidcserver/internal"
	storagepb "github.com/pardot/deci/proto/deci/storage/v1beta1"
	"github.com/pardot/deci/storage"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	// reValidPublicRedirectUri is a fairly strict regular expression that must
	// match against the redirect URI for a 'public' client. It intentionally may
	// not match all URLs that are technically valid, but is it meant to match
	// all commonly constructed ones, without inadvertently falling victim to
	// parser bugs or parser inconsistencies (e.g.,
	// https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	reValidPublicRedirectURI = regexp.MustCompile(`\Ahttp://localhost(?::[0-9]{1,5})?(?:|/[A-Za-z0-9./_-]{0,1000})\z`)
)

// authErr is an error response to an authorization request.
// See: https://tools.ietf.org/html/rfc6749#section-4.1.2.1
type authErr struct {
	State       string
	RedirectURI string
	Type        string
	Description string
}

func (err *authErr) Status() int {
	if err.State == errServerError {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

func (err *authErr) Error() string {
	return err.Description
}

func (err *authErr) Handle() (http.Handler, bool) {
	// Didn't get a valid redirect URI.
	if err.RedirectURI == "" {
		return nil, false
	}

	hf := func(w http.ResponseWriter, r *http.Request) {
		v := url.Values{}
		v.Add("state", err.State)
		v.Add("error", err.Type)
		if err.Description != "" {
			v.Add("error_description", err.Description)
		}
		var redirectURI string
		if strings.Contains(err.RedirectURI, "?") {
			redirectURI = err.RedirectURI + "&" + v.Encode()
		} else {
			redirectURI = err.RedirectURI + "?" + v.Encode()
		}
		http.Redirect(w, r, redirectURI, http.StatusSeeOther)
	}
	return http.HandlerFunc(hf), true
}

func tokenErr(w http.ResponseWriter, typ, description string, statusCode int) error {
	data := struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitempty"`
	}{typ, description}
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal token error response: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(statusCode)
	_, err = w.Write(body)
	return err
}

// these are standard constants, worth having here.
// nolint:deadcode,varcheck,unused
const (
	errInvalidRequest          = "invalid_request"
	errUnauthorizedClient      = "unauthorized_client"
	errAccessDenied            = "access_denied"
	errUnsupportedResponseType = "unsupported_response_type"
	errInvalidScope            = "invalid_scope"
	errServerError             = "server_error"
	errTemporarilyUnavailable  = "temporarily_unavailable"
	errUnsupportedGrantType    = "unsupported_grant_type"
	errInvalidGrant            = "invalid_grant"
	errInvalidClient           = "invalid_client"
)

const (
	scopeOfflineAccess     = "offline_access" // Request a refresh token.
	scopeOpenID            = "openid"
	scopeGroups            = "groups"
	scopeEmail             = "email"
	scopeProfile           = "profile"
	scopeFederatedID       = "federated:id"
	scopeCrossClientPrefix = "audience:server:client_id:"
)

const (
	redirectURIOOB = "urn:ietf:wg:oauth:2.0:oob"
)

const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
)

const (
	responseTypeCode    = "code"     // "Regular" flow
	responseTypeToken   = "token"    // Implicit flow for frontend apps.
	responseTypeIDToken = "id_token" // ID Token in url fragment
)

func parseScopes(scopes []string) Scopes {
	var s Scopes
	for _, scope := range scopes {
		switch scope {
		case scopeOfflineAccess:
			s.OfflineAccess = true
		case scopeGroups:
			s.Groups = true
		}
	}
	return s
}

// The hash algorithm for the at_hash is determined by the signing
// algorithm used for the id_token. From the spec:
//
//    ...the hash algorithm used is the hash algorithm used in the alg Header
//    Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256,
//    hash the access_token value with SHA-256
//
// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
var hashForSigAlg = map[jose.SignatureAlgorithm]func() hash.Hash{
	jose.RS256: sha256.New,
	jose.RS384: sha512.New384,
	jose.RS512: sha512.New,
	jose.ES256: sha256.New,
	jose.ES384: sha512.New384,
	jose.ES512: sha512.New,
}

// Compute an at_hash from a raw access token and a signature algorithm
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
func accessTokenHash(alg jose.SignatureAlgorithm, accessToken string) (string, error) {
	newHash, ok := hashForSigAlg[alg]
	if !ok {
		return "", fmt.Errorf("unsupported signature algorithm: %s", alg)
	}

	hash := newHash()
	if _, err := io.WriteString(hash, accessToken); err != nil {
		return "", fmt.Errorf("computing hash: %v", err)
	}
	sum := hash.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

type audience []string

func (a audience) contains(aud string) bool {
	for _, e := range a {
		if aud == e {
			return true
		}
	}
	return false
}

func (a audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

type idTokenClaims struct {
	Issuer           string   `json:"iss"`
	Subject          string   `json:"sub"`
	Audience         audience `json:"aud"`
	Expiry           int64    `json:"exp"`
	IssuedAt         int64    `json:"iat"`
	AuthorizingParty string   `json:"azp,omitempty"`
	Nonce            string   `json:"nonce,omitempty"`

	AccessTokenHash string `json:"at_hash,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	Groups []string `json:"groups,omitempty"`

	ACR *string  `json:"acr,omitempty"`
	AMR []string `json:"amr,omitempty"`

	Name string `json:"name,omitempty"`

	FederatedIDClaims *federatedIDClaims `json:"federated_claims,omitempty"`
}

type federatedIDClaims struct {
	ConnectorID string `json:"connector_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
}

func (s *Server) newAccessToken(clientID string, claims *storagepb.Claims, scopes []string, nonce, connID string) (accessToken string, err error) {
	idToken, _, err := s.newIDToken(clientID, claims, scopes, nonce, storage.NewID(), connID)
	return idToken, err
}

func (s *Server) newIDToken(clientID string, claims *storagepb.Claims, scopes []string, nonce, accessToken, connID string) (idToken string, expiry time.Time, err error) {
	issuedAt := s.now()
	expiry = issuedAt.Add(s.idTokensValidFor)

	sub := &internal.IDTokenSubject{
		UserId: claims.UserId,
		ConnId: connID,
	}

	subjectString, err := internal.Marshal(sub)
	if err != nil {
		s.logger.Errorf("failed to marshal offline session ID: %v", err)
		return "", expiry, fmt.Errorf("failed to marshal offline session ID: %v", err)
	}

	tok := idTokenClaims{
		Issuer:   s.issuerURL.String(),
		Subject:  subjectString,
		Nonce:    nonce,
		Expiry:   expiry.Unix(),
		IssuedAt: issuedAt.Unix(),
		AMR:      claims.Amr,
	}
	if claims.Acr != nil {
		tok.ACR = &claims.Acr.Value
	}

	signingAlg, err := s.signer.SignerAlg(context.TODO())
	if err != nil {
		return "", expiry, err
	}

	if accessToken != "" {
		atHash, err := accessTokenHash(signingAlg, accessToken)
		if err != nil {
			s.logger.Errorf("error computing at_hash: %v", err)
			return "", expiry, fmt.Errorf("error computing at_hash: %v", err)
		}
		tok.AccessTokenHash = atHash
	}

	for _, scope := range scopes {
		switch {
		case scope == scopeEmail:
			tok.Email = claims.Email
			tok.EmailVerified = &claims.EmailVerified
		case scope == scopeGroups:
			tok.Groups = claims.Groups
		case scope == scopeProfile:
			tok.Name = claims.Username
		case scope == scopeFederatedID:
			tok.FederatedIDClaims = &federatedIDClaims{
				ConnectorID: connID,
				UserID:      claims.UserId,
			}
		default:
			peerID, ok := parseCrossClientScope(scope)
			if !ok {
				// Ignore unknown scopes. These are already validated during the
				// initial auth request.
				continue
			}
			isTrusted, err := s.validateCrossClientTrust(clientID, peerID)
			if err != nil {
				return "", expiry, err
			}
			if !isTrusted {
				// TODO(ericchiang): propagate this error to the client.
				return "", expiry, fmt.Errorf("peer (%s) does not trust client", peerID)
			}
			tok.Audience = append(tok.Audience, peerID)
		}
	}

	if len(tok.Audience) == 0 {
		// Client didn't ask for cross client audience. Set the current
		// client as the audience.
		tok.Audience = audience{clientID}
	} else {
		// Client asked for cross client audience:
		// if the current client was not requested explicitly
		if !tok.Audience.contains(clientID) {
			// by default it becomes one of entries in Audience
			tok.Audience = append(tok.Audience, clientID)
		}
		// The current client becomes the authorizing party.
		tok.AuthorizingParty = clientID
	}

	payload, err := json.Marshal(tok)
	if err != nil {
		return "", expiry, fmt.Errorf("could not serialize claims: %v", err)
	}

	signed, err := s.signer.Sign(context.TODO(), payload)
	if err != nil {
		return "", expiry, fmt.Errorf("failed to sign payload: %v", err)
	}
	return string(signed), expiry, nil
}

// parse the initial request from the OAuth2 client.
func (s *Server) parseAuthorizationRequest(r *http.Request) (req *storagepb.AuthRequest, oauth2Err *authErr) {
	if err := r.ParseForm(); err != nil {
		return req, &authErr{"", "", errInvalidRequest, "Failed to parse request body."}
	}
	q := r.Form
	redirectURI, err := url.QueryUnescape(q.Get("redirect_uri"))
	if err != nil {
		return req, &authErr{"", "", errInvalidRequest, "No redirect_uri provided."}
	}

	clientID := q.Get("client_id")
	state := q.Get("state")
	nonce := q.Get("nonce")
	// Some clients, like the old go-oidc, provide extra whitespace. Tolerate this.
	scopes := strings.Fields(q.Get("scope"))
	responseTypes := strings.Fields(q.Get("response_type"))
	acrValues := strings.Fields(q.Get("acr_values"))

	client, err := s.clients.GetClient(clientID)
	if err != nil {
		if isNoSuchClientErr(err) {
			description := fmt.Sprintf("Invalid client_id (%q).", clientID)
			return req, &authErr{"", "", errUnauthorizedClient, description}
		}
		s.logger.Errorf("Failed to get client: %v", err)
		return req, &authErr{"", "", errServerError, ""}
	}

	if !validateRedirectURI(client, redirectURI) {
		description := fmt.Sprintf("Unregistered redirect_uri (%q).", redirectURI)
		return req, &authErr{"", "", errInvalidRequest, description}
	}

	// From here on out, we want to redirect back to the client with an error.
	newErr := func(typ, format string, a ...interface{}) *authErr {
		return &authErr{state, redirectURI, typ, fmt.Sprintf(format, a...)}
	}

	var (
		unrecognized  []string
		invalidScopes []string
	)
	hasOpenIDScope := false
	for _, scope := range scopes {
		switch scope {
		case scopeOpenID:
			hasOpenIDScope = true
		case scopeOfflineAccess, scopeEmail, scopeProfile, scopeGroups, scopeFederatedID:
		default:
			peerID, ok := parseCrossClientScope(scope)
			if !ok {
				unrecognized = append(unrecognized, scope)
				continue
			}

			isTrusted, err := s.validateCrossClientTrust(clientID, peerID)
			if err != nil {
				return req, newErr(errServerError, "Internal server error.")
			}
			if !isTrusted {
				invalidScopes = append(invalidScopes, scope)
			}
		}
	}
	if !hasOpenIDScope {
		return req, newErr("invalid_scope", `Missing required scope(s) ["openid"].`)
	}
	if len(unrecognized) > 0 {
		return req, newErr("invalid_scope", "Unrecognized scope(s) %q", unrecognized)
	}
	if len(invalidScopes) > 0 {
		return req, newErr("invalid_scope", "Client can't request scope(s) %q", invalidScopes)
	}

	var rt struct {
		code    bool
		idToken bool
		token   bool
	}

	for _, responseType := range responseTypes {
		switch responseType {
		case responseTypeCode:
			rt.code = true
		case responseTypeIDToken:
			rt.idToken = true
		case responseTypeToken:
			rt.token = true
		default:
			return req, newErr("invalid_request", "Invalid response type %q", responseType)
		}

		if !s.supportedResponseTypes[responseType] {
			return req, newErr(errUnsupportedResponseType, "Unsupported response type %q", responseType)
		}
	}

	if len(responseTypes) == 0 {
		return req, newErr("invalid_requests", "No response_type provided")
	}

	if rt.token && !rt.code && !rt.idToken {
		// "token" can't be provided by its own.
		//
		// https://openid.net/specs/openid-connect-core-1_0.html#Authentication
		return req, newErr("invalid_request", "Response type 'token' must be provided with type 'id_token' and/or 'code'")
	}
	if !rt.code {
		// Either "id_token code" or "id_token" has been provided which implies the
		// implicit flow. Implicit flow requires a nonce value.
		//
		// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
		if nonce == "" {
			return req, newErr("invalid_request", "Response type 'token' requires a 'nonce' value.")
		}
	}
	if rt.token {
		if redirectURI == redirectURIOOB {
			err := fmt.Sprintf("Cannot use response type 'token' with redirect_uri '%s'.", redirectURIOOB)
			return req, newErr("invalid_request", err)
		}
	}

	return &storagepb.AuthRequest{
		Id:                  storage.NewID(),
		ClientId:            client.ID,
		State:               state,
		Nonce:               nonce,
		ForceApprovalPrompt: q.Get("approval_prompt") == "force",
		Scopes:              scopes,
		RedirectUri:         redirectURI,
		ResponseTypes:       responseTypes,
		AcrValues:           acrValues,
	}, nil
}

func parseCrossClientScope(scope string) (peerID string, ok bool) {
	if ok = strings.HasPrefix(scope, scopeCrossClientPrefix); ok {
		peerID = scope[len(scopeCrossClientPrefix):]
	}
	return
}

func (s *Server) validateCrossClientTrust(clientID, peerID string) (trusted bool, err error) {
	if peerID == clientID {
		return true, nil
	}
	peer, err := s.clients.GetClient(peerID)
	if err != nil {
		if !isNoSuchClientErr(err) {
			s.logger.Errorf("Failed to get client: %v", err)
			return false, err
		}
		return false, nil
	}
	for _, id := range peer.TrustedPeers {
		if id == clientID {
			return true, nil
		}
	}
	return false, nil
}

func validateRedirectURI(client *Client, redirectURI string) bool {
	if !client.Public {
		for _, uri := range client.RedirectURIs {
			if redirectURI == uri {
				return true
			}
		}
		return false
	}

	if redirectURI == redirectURIOOB {
		return true
	}

	return reValidPublicRedirectURI.MatchString(redirectURI)
}
