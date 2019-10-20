package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// writeError handles the passed error appropriately. After calling this, the
// HTTP sequence should be considered complete.
//
// For errors in the authorization endpoint, the user will be redirected with
// the code appended to the redirect URL.
// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
//
// For unknown errors, an InternalServerError response will be sent
func writeError(w http.ResponseWriter, req *http.Request, err error) error {
	switch err := err.(type) {
	case *authError:
		redir, perr := url.Parse(err.redirectURI)
		if err != nil {
			return fmt.Errorf("failed to parse redirect URI %q: %w", err.redirectURI, perr)
		}
		v := redir.Query()
		if err.state != "" {
			v.Add("state", err.state)
		}
		v.Add("error", string(err.code))
		if err.description != "" {
			v.Add("error_description", err.description)
		}
		http.Redirect(w, req, redir.String(), http.StatusTemporaryRedirect)

	case *httpErr:
		m := err.message
		if m == "" {
			m = "Internal error"
		}
		http.Error(w, err.message, err.code)

	case *tokenError:
		w.Header().Add("Content-Type", "application/json;charset=UTF-8")
		// https://tools.ietf.org/html/rfc6749#section-5.2
		if err.code == tokenErrorCodeInvalidClient {
			if err.wwwauthenticate != "" {
				w.Header().Add("WWW-Authenticate", err.wwwauthenticate)
			}
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return fmt.Errorf("failed to write token error json body: %w", err)
		}

	default:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	return nil
}

// newInvalidRedirectError is used if the passed redirect URI is not valid.
// If this is the case the error is returned directly to the user, and the
// redirect never called.
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
func newInvalidRedirectError() error {
	return &httpErr{
		code:    http.StatusBadRequest,
		message: "Invalid redirect URI",
	}
}

type httpErr struct {
	code int
	// message is presented to the user, so this should be considered.
	// if it's not set, "Internal error" will be used.
	message string
	// cause message is presented in the Error() output, so it should be used
	// for internal text
	causeMsg string
	cause    error
}

func (h *httpErr) Error() string {
	m := h.causeMsg
	if m == "" {
		m = h.message
	}
	str := fmt.Sprintf("http error %d: %s", h.code, m)
	if h.cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, h.cause.Error())
	}
	return str
}

func (h *httpErr) Unwrap() error {
	return h.cause
}

type authErrorCode string

const ( // https://tools.ietf.org/html/rfc6749#section-4.1.2.1
	authErrorCodeInvalidRequest           authErrorCode = "invalid_request"
	authErrorCodeUnauthorizedClient       authErrorCode = "unauthorized_client"
	authErrorCodeAccessDenied             authErrorCode = "access_denied"
	authErrorCodeUnsupportedResponseType  authErrorCode = "unsupported_response_type"
	authErrorCodeInvalidScope             authErrorCode = "invalid_scope"
	authErrorCodeErrServerError           authErrorCode = "server_error"
	authErrorCodeErrTemporarilyUnvailable authErrorCode = "temporarily_unavailable"
)

type authError struct {
	state       string
	code        authErrorCode
	description string
	redirectURI string
	cause       error
}

func (a *authError) Error() string {
	str := fmt.Sprintf("%s error in authorization request: %s", a.code, a.description)
	if a.cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, a.cause.Error())
	}
	return str
}

func (a *authError) Unwrap() error {
	return a.cause
}

// addRedirectToError can attach a redirect URI to an error. This is uncommon,
// but useful when the redirect URI is configured at the client only, and not
// passed in the authorization request. If the error cannot make use of this, it
// will be ignored and the original error returned
func addRedirectToError(err error, redirectURI string) error {
	if err, ok := err.(*authError); ok {
		err.redirectURI = redirectURI
		return err
	}
	return err
}

type tokenErrorCode string

const ( // https://tools.ietf.org/html/rfc6749#section-5.2
	tokenErrorCodeInvalidRequest       tokenErrorCode = "invalid_request"
	tokenErrorCodeInvalidClient        tokenErrorCode = "invalid_client"
	tokenErrorCodeInvalidGrant         tokenErrorCode = "invalid_grant"
	tokenErrorCodeUnauthorizedClient   tokenErrorCode = "unauthorized_client"
	tokenErrorCodeUnsupportedGrantType tokenErrorCode = "unsupported_grant_type"
	tokenErrorCodeInvalidScope         tokenErrorCode = "invalid_scope"
)

type tokenError struct {
	code            tokenErrorCode `json:"error,omitempty"`
	description     string         `json:"error_description,omitemptu"`
	errorURI        string         `json:"error_uri,omitempty"`
	cause           error          `json:"-"`
	wwwauthenticate string         `json:"-"`
}

func (t *tokenError) Error() string {
	return fmt.Sprintf("%s error in authorization request: %s", t.code, t.description)
}

func (t *tokenError) Unwrap() error {
	return t.cause
}
