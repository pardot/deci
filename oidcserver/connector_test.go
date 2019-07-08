package oidcserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

// NewCallbackConnector returns a mock connector which requires no user interaction. It always returns
// the same (fake) identity.
func NewCallbackConnector(logger logrus.FieldLogger) Connector {
	return &Callback{
		Identity: Identity{
			UserID:        "0-385-28089-0",
			Username:      "Kilgore Trout",
			Email:         "kilgore@kilgore.trout",
			EmailVerified: true,
			Groups:        []string{"authors"},
			ConnectorData: connectorData,
		},
		Logger: logger,
	}
}

var (
	_ CallbackConnector = &Callback{}
	_ RefreshConnector  = &Callback{}
)

// Callback is a connector that requires no user interaction and always returns the same identity.
type Callback struct {
	// The returned identity.
	Identity Identity
	Logger   logrus.FieldLogger
}

// LoginURL returns the URL to redirect the user to login with.
func (m *Callback) LoginURL(s Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

var connectorData = []byte("foobar")

// HandleCallback parses the request and returns the user's identity
func (m *Callback) HandleCallback(s Scopes, r *http.Request) (Identity, error) {
	return m.Identity, nil
}

// Refresh updates the identity during a refresh token request.
func (m *Callback) Refresh(ctx context.Context, s Scopes, identity Identity) (Identity, error) {
	return m.Identity, nil
}
