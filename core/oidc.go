package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	corestate "github.com/pardot/deci/proto/deci/corestate/v1beta1"
	"github.com/pardot/deci/storage"
	"gopkg.in/square/go-jose.v2"
)

const (
	authRequestKeyspace = "oidc-auth-request"
	authCodeKeyspace    = "oidc-auth-code"
	accessTokenKeyspace = "oidc-access-token"
)

const (
	tokenLength = 56 // max useful for bcrypt
)

// Storage is used to maintain authorization flow state.
type Storage storage.Storage

// Signer is used for signing identity tokens
type Signer interface {
	// SignerAlg returns the algorithm the signer uses
	SignerAlg(ctx context.Context) (jose.SignatureAlgorithm, error)
	// Sign the provided data
	Sign(ctx context.Context, data []byte) (signed []byte, err error)
	// VerifySignature verifies the signature given token against the current signers
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

// ClientSource is used for validating client informantion for the general flow
type ClientSource interface {
	// IsValidClientID should return true if the passed client ID is valid
	IsValidClientID(clientID string) (ok bool, err error)
	// IsUnauthenticatedClient is used to check if the client should be required
	// to pass a client secret. If not, this will not be checked
	IsUnauthenticatedClient(clientID string) (ok bool, err error)
	// ValidateClientSecret should confirm if the passed secret is valid for the
	// given client
	ValidateClientSecret(clientID, clientSecret string) (ok bool, err error)
	// ValidateRedirectURI should confirm if the given redirect is valid for the client. It should
	// compare as per https://tools.ietf.org/html/rfc3986#section-6
	ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error)
}

// OIDC can be used to handle the various parts of the OIDC auth flow.
type OIDC struct {
	storage Storage
	clients ClientSource
	signer  Signer

	authValidityTime time.Duration
	codeValidityTime time.Duration

	now func() time.Time
}

func NewOIDC(storage Storage, clientSource ClientSource, signer Signer) (*OIDC, error) {
	return &OIDC{
		storage: storage,
		clients: clientSource,
	}, nil
}

type AuthorizationResponse struct {
	AuthID string
}

// StartAuthorization can be used to handle a request to the auth endpoint. It
// will parse and validate the incoming request, returning a unique identifier.
// If an error was returned, it should be assumed that this has been returned to
// the user appropriately. Otherwise, no response will be written. The caller
// can then use this request to implement the appropriate auth flow. The authID
// should be kept and treated as sensitive - it will be used to mark the request
// as Authorized.
//
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
func (o *OIDC) StartAuthorization(w http.ResponseWriter, req *http.Request) (*AuthorizationResponse, error) {
	authreq, err := parseAuthRequest(req)
	if err != nil {
		writeError(w, req, err)
		return nil, fmt.Errorf("failed to parse auth endpoint request: %w", err)
	}

	// TODO - validate this error flow

	cidok, err := o.clients.IsValidClientID(authreq.ClientID)
	if err != nil {
		aerr := &authError{state: authreq.State, code: authErrorCodeErrServerError, description: "internal error", cause: err}
		writeError(w, req, aerr)
		return nil, aerr
	}
	if !cidok {
		cerr := &authError{state: authreq.State, code: authErrorCodeUnauthorizedClient, description: "client does not exist"}
		writeError(w, req, cerr)
		return nil, cerr
	}

	redirok, err := o.clients.ValidateClientRedirectURI(authreq.ClientID, authreq.RedirectURI)
	if err != nil {
		rerr := &authError{state: authreq.State, code: authErrorCodeErrServerError, description: "internal error", cause: err}
		writeError(w, req, rerr)
		return nil, rerr
	}
	if !redirok {
		rerr := newInvalidRedirectError()
		writeError(w, req, rerr)
		return nil, rerr
	}

	authFlowID := mustGenerateID()

	ar := &corestate.AuthRequest{
		ClientId:    authreq.ClientID,
		RedirectUri: authreq.RedirectURI,
		State:       authreq.State,
		Scopes:      authreq.Scopes,
		Nonce:       req.FormValue("nonce"),
	}

	switch authreq.ResponseType {
	case responseTypeCode:
		ar.ResponseType = corestate.AuthRequest_CODE
	case responseTypeImplicit:
		ar.ResponseType = corestate.AuthRequest_TOKEN
	default:
		err := &authError{state: authreq.State, code: authErrorCodeUnsupportedResponseType, description: "response type must be code or token"}
		writeError(w, req, err)
		return nil, err
	}

	if _, err := o.storage.PutWithExpiry(req.Context(), authRequestKeyspace, authFlowID, 0, ar, o.now().Add(o.authValidityTime)); err != nil {
		herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to put authReq to storage", cause: err}
		writeError(w, req, herr)
		return nil, herr
	}

	return &AuthorizationResponse{
		AuthID: authFlowID,
	}, nil
}

// FinishAuthorization should be called once the consumer has validated the
// identity of the user. This will return the appropriate response directly to
// the passed http context, which should be considered finalized when this is
// called. Note: This does not have to be the same http request in which
// Authorization was started, but the authID field will need to be tracked and
// consistent.
//
// The scopes this request has been granted with should be included. Metadata
// can be passed, that will be made available to requests to userinfo and token
// issue/refresh. This is application-specific, and should be used to track
// information needed to serve those endpoints. Claims that should be used for
// the token should also be passed.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func (o *OIDC) FinishAuthorization(w http.ResponseWriter, req *http.Request, authFlowID string, scopes []string, claims Claims, metadata proto.Message) error {

	ar := &corestate.AuthRequest{}
	if _, err := o.storage.Get(req.Context(), authRequestKeyspace, authFlowID, ar); err != nil {
		// TODO - maybe a clearer error as to if this is transient, or something
		// fatal like code not existing.
		herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to get auth request from storage", cause: err}
		writeError(w, req, herr)
		return herr
	}

	// verify the session token matches

	// TODO delete the record, to avoid potential replays

	switch ar.ResponseType {
	case corestate.AuthRequest_CODE:
		return o.finishCodeAuthorization(w, req, ar, scopes, claims, metadata)
	case corestate.AuthRequest_TOKEN:
		panic("TODO - implicit flow")
	default:
		herr := &httpErr{code: http.StatusInternalServerError, causeMsg: fmt.Sprintf("unknown ResponseType %s", ar.ResponseType.String())}
		writeError(w, req, herr)
		return herr
	}
}

func (o *OIDC) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, authReq *corestate.AuthRequest, scopes []string, claims Claims, metadata proto.Message) error {
	// authCode, err := newToken(32)
	// if err != nil {
	// 	herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to generate code token", cause: err}
	// 	writeError(w, req, herr)
	// 	return herr
	// }

	// salt, hash, err := hashToken(authCode)
	// if err != nil {
	// 	herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to hash token", cause: err}
	// 	writeError(w, req, herr)
	// 	return herr
	// }

	// sclaims, err := goToPBStruct(claims)
	// if err != nil {
	// 	herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to convert claims to proto", cause: err}
	// 	writeError(w, req, herr)
	// 	return herr
	// }

	// anym, err := ptypes.MarshalAny(metadata)
	// if err != nil {
	// 	herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to marshal metadata to any", cause: err}
	// 	writeError(w, req, herr)
	// 	return herr
	// }

	// ac := &corestate.AuthCode{
	// 	AuthRequest: authReq,
	// 	Claims:      sclaims,
	// 	Metadata:    anym,
	// }

	// if _, err := o.storage.PutWithExpiry(req.Context(), authCodeKeyspace, hash, 0, ac, o.now().Add(o.codeValidityTime)); err != nil {
	// 	herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to put authReq to storage", cause: err}
	// 	writeError(w, req, herr)
	// 	return herr
	// }

	// codeResp := &codeAuthResponse{
	// 	RedirectURI: authReq.RedirectUri,
	// 	State:       authReq.State,
	// 	Code:        fmt.Sprintf("%s.%s", salt, authCode),
	// }

	// if err := sendCodeAuthResponse(w, req, codeResp); err != nil {
	// 	writeError(w, req, err)
	// 	return err
	// }

	return nil
}

type TokenRequest struct {
	IsRefresh        bool
	RefreshRequested bool

	Metadata *any.Any
}

type TokenResponse struct {
	AllowRefresh bool
	Claims       Claims

	Metadata *any.Any
}

// Token is used to handle the access token endpoint for code flow requests.
// This can handle both the initial access token request, as well as subsequent
// calls for refreshes.
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (o *OIDC) Token(w http.ResponseWriter, req *http.Request, handler func(req *TokenRequest) (*TokenResponse, error)) error {
	treq, err := parseTokenRequest(req)
	if err != nil {
		writeError(w, req, err)
		return err
	}

	// re-hash the presented code.
	csp := strings.SplitN(treq.Code, ".", 2)
	if len(csp) != 2 {
		terr := &tokenError{code: tokenErrorCodeInvalidRequest, description: "invalid code"}
		writeError(w, req, terr)
		return terr
	}

	// chash, err := hashTokenWithSalt(csp[0], csp[1])
	// if err != nil {
	// 	terr := &tokenError{code: tokenErrorCodeInvalidRequest, description: "invalid code", cause: err}
	// 	writeError(w, req, terr)
	// 	return terr
	// }
	chash := "1234"

	// fetch the code, and make sure this isn't some replay. if it is, discard
	// both the code and the existing authorization code
	ac := &corestate.AuthCode{}
	if _, err := o.storage.Get(req.Context(), authCodeKeyspace, chash, ac); err != nil {
		// TODO - maybe a clearer error as to if this is transient, or something
		// fatal like code not existing.
		herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to get auth code from storage", cause: err}
		writeError(w, req, herr)
		return herr
	}

	// The code already has a token associated with it. Assume we're under a
	// replay attack, and delete both the code and the issued access token (in
	// case the malicious request got in first)
	if ac.AccessToken != nil {
		at := tokenFromPB(ac.AccessToken)

		if err := o.storage.Delete(req.Context(), authCodeKeyspace, chash); err != nil {
			herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to delete auth code from storage", cause: err}
			writeError(w, req, herr)
			return herr
		}
		if err := o.storage.Delete(req.Context(), accessTokenKeyspace, at.ID()); err != nil {
			herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to delete access token storage", cause: err}
			writeError(w, req, herr)
			return herr
		}
		terr := &tokenError{code: tokenErrorCodeInvalidRequest, description: "code already redeemed", cause: err}
		writeError(w, req, terr)
		return terr
	}

	// validate the client
	cok, err := o.clients.ValidateClientSecret(treq.ClientID, treq.ClientSecret)
	if err != nil {
		herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to check client id & secret", cause: err}
		writeError(w, req, herr)
		return herr
	}
	if !cok {
		terr := &tokenError{code: tokenErrorCodeUnauthorizedClient}
		writeError(w, req, terr)
		return terr
	}

	// Call the handler with information about the request, and get the response.
	tr := &TokenRequest{
		IsRefresh:        false, // TODO
		RefreshRequested: false, // TODO
		Metadata:         ac.Metadata,
	}

	tresp, err := handler(tr)
	if err != nil {
		herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "handler error", cause: err}
		writeError(w, req, herr)
		return herr
	}

	// create a new access token

	// accessToken, err := newToken(32)
	// if err != nil {
	// 	herr := &httpErr{code: http.StatusInternalServerError, causeMsg: "failed to generate access token", cause: err}
	// 	writeError(w, req, herr)
	// 	return herr
	// }

	at := &corestate.AccessToken{
		Metadata: tresp.Metadata,
		Claims:   ac.Claims,
	}
	_ = at

	// Save the access token with the right expiry

	tar := &tokenAuthResponse{
		Token: "",
	}

	sendTokenAuthResponse(w, req, tar)

	// create an auth token entry
	// sign the id token
	// return to user
	return nil
}

type UserinfoRequest struct {
	Claims   Claims
	Metadata *any.Any
}

// Userinfo can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// response data to the passed JSON encoder. This could be the stored claims if
// the ID Token contents are sufficent, otherwise this should be the desired
// response. This will return the desired information in an unsigned format.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (o *OIDC) Userinfo(w http.ResponseWriter, req *http.Request, handler func(w *json.Encoder, uireq *UserinfoRequest) error) (err error) {
	return nil
}

// mustGenerateID returns a new, unique identifier. If it can't, it will panic
func mustGenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
