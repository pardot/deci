package oidcserverv2

import (
	"testing"

	"github.com/pardot/deci/oidcserver"
)

func TestRedirectURIs(t *testing.T) {
	cmgr := &clientMgr{
		clients: &simpleClientSource{
			Clients: map[string]*oidcserver.Client{
				"public": &oidcserver.Client{
					ID:     "public",
					Public: true,
				},
				"private": &oidcserver.Client{
					ID:     "private",
					Public: false,
					RedirectURIs: []string{
						"http://localhost",
					},
				},
			},
		},
	}

	v, err := cmgr.ValidateClientRedirectURI("public", "http://localhost:420/callback")
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Error("localhost callback should be valid for public client, but was not")
	}

	v, err = cmgr.ValidateClientRedirectURI("private", "http://localhost:420/callback")
	if err != nil {
		t.Fatal(err)
	}
	if v {
		t.Error("private client should require exact match for redirect URI")
	}

	v, err = cmgr.ValidateClientRedirectURI("private", "http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Error("exact match for redirect URI should be acceptable")
	}
}
