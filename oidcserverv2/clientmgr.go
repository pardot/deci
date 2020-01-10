package oidcserverv2

import (
	"crypto/subtle"
	"net"
	"net/url"

	"github.com/pardot/deci/oidcserver"
	"github.com/pardot/oidc/core"
)

var _ core.ClientSource = (*clientMgr)(nil)

type clientMgr struct {
	clients oidcserver.ClientSource
}

func (c *clientMgr) IsValidClientID(clientID string) (ok bool, err error) {
	_, err = c.clients.GetClient(clientID)
	if err != nil {
		if _, ok := err.(oidcserver.ErrNoSuchClient); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *clientMgr) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	// we don't have the concept of this
	return false, nil
}

func (c *clientMgr) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cl, err := c.clients.GetClient(clientID)
	if err != nil {
		if _, ok := err.(oidcserver.ErrNoSuchClient); ok {
			return false, nil
		}
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(cl.Secret), []byte(clientSecret)) == 1, nil
}

func (c *clientMgr) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cl, err := c.clients.GetClient(clientID)
	if err != nil {
		if _, ok := err.(oidcserver.ErrNoSuchClient); ok {
			return false, nil
		}
		return false, err
	}

	if cl.Public { // oob or localhost, check a bit more leniently
		if redirectURI == "urn:ietf:wg:oauth:2.0:oob" {
			return true, nil
		}

		u, err := url.Parse(redirectURI)
		if err != nil {
			return false, err
		}
		if u.Scheme != "http" {
			return false, nil
		}
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return false, err
		}
		if host == "localhost" {
			return true, nil
		}
	}

	for _, ru := range cl.RedirectURIs {
		if ru == redirectURI {
			return true, nil
		}
	}

	return false, nil
}
