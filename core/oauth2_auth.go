package core

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type responseType string

const (
	responseTypeCode     responseType = "code"
	responseTypeImplicit responseType = "token"
)

type authRequest struct {
	ClientID     string
	RedirectURI  string
	State        string
	Scopes       []string
	ResponseType responseType
}

// parseAuthRequest can be used to process an oauth2 authentication request,
// returning information about it. It can handle both the code and implicit auth
// types. If an error is returned, it should be passed to the user via
// writeError
//
// https://tools.ietf.org/html/rfc6749#section-4.1.1
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func parseAuthRequest(req *http.Request) (authReq *authRequest, err error) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return nil, &httpErr{code: http.StatusBadRequest, message: "method must be POST or GET"}
	}

	if err := req.ParseForm(); err != nil {
		return nil, &httpErr{code: http.StatusBadRequest, message: "failed to parse request", cause: err}
	}

	rts := req.FormValue("response_type")
	cid := req.FormValue("client_id")
	ruri := req.FormValue("redirect_uri")
	scope := req.FormValue("scope")
	state := req.FormValue("state")

	var rt responseType
	switch rts {
	case string(responseTypeCode):
		rt = responseTypeCode
	case string(responseTypeImplicit):
		rt = responseTypeImplicit
	default:
		return nil, &authError{
			state:       state,
			code:        authErrorCodeInvalidRequest,
			description: `response_type must be "code" or "token"`,
			redirectURI: ruri,
		}
	}

	if cid == "" {
		return nil, &authError{
			state:       state,
			code:        authErrorCodeInvalidRequest,
			description: "client_id must be specified",
			redirectURI: ruri,
		}
	}

	return &authRequest{
		ClientID:     cid,
		RedirectURI:  ruri,
		State:        state,
		Scopes:       strings.Split(strings.TrimSpace(scope), " "),
		ResponseType: rt,
	}, nil
}

type codeAuthResponse struct {
	RedirectURI string
	State       string
	Code        string
}

// sendCodeAuthResponse sends the appropriate response to an auth request of
// response_type code, aka "Code flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2
func sendCodeAuthResponse(w http.ResponseWriter, req *http.Request, resp *codeAuthResponse) error {
	redir, err := authResponse(resp.RedirectURI, resp.State)
	if err != nil {
		return err
	}
	v := redir.Query()
	v.Add("code", resp.Code)
	http.Redirect(w, req, redir.String(), http.StatusTemporaryRedirect)
	return nil
}

type tokenType string

const ( // https://tools.ietf.org/html/rfc6749#section-7.1 , https://tools.ietf.org/html/rfc6750
	tokenTypeBearer tokenType = "Bearer"
)

type tokenAuthResponse struct {
	RedirectURI string
	State       string
	Token       string
	TokenType   tokenType
	Scopes      []string
	ExpiresIn   time.Duration
}

// sendTokenAuthResponse sends the appropriate response to an auth request of
// response_type token, aka "Implicit flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.2.2
func sendTokenAuthResponse(w http.ResponseWriter, req *http.Request, resp *tokenAuthResponse) error {
	redir, err := authResponse(resp.RedirectURI, resp.State)
	if err != nil {
		return err
	}
	v := redir.Query()
	v.Add("access_token", resp.Token)
	v.Add("token_type", string(resp.TokenType))
	if resp.ExpiresIn != 0 {
		v.Add("expires_in", fmt.Sprintf("%f", resp.ExpiresIn.Seconds()))
	}
	if resp.Scopes != nil {
		v.Add("scope", strings.Join(resp.Scopes, " "))
	}
	http.Redirect(w, req, redir.String(), http.StatusTemporaryRedirect)
	return nil
}

func authResponse(redir, state string) (*url.URL, error) {
	r, err := url.Parse(redir)
	if err != nil {
		return nil, fmt.Errorf("failed parsing redirect uri %s: %w", redir, err)
	}
	v := r.Query()
	if state != "" {
		v.Add("state", state)
	}
	return r, nil
}
