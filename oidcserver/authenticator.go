package oidcserver

import (
	"context"
	"fmt"

	storagepb "github.com/heroku/deci/proto/deci/storage/v1beta1"
)

// Authenticator is capable of associating the user's identity with a given
// authID, then returning the final redirect URL.
//
// Server implements Authenticator.
type Authenticator interface {
	// Authenticate associates the user's identity with the given authID, then
	// returns final redirect URL.
	Authenticate(ctx context.Context, authID string, ident Identity) (returnURL string, err error)
}

func (s *Server) Authenticate(ctx context.Context, authID string, ident Identity) (returnURL string, err error) {
	claims := &storagepb.Claims{
		UserId:        ident.UserID,
		Username:      ident.Username,
		Email:         ident.Email,
		EmailVerified: ident.EmailVerified,
		Groups:        ident.Groups,
	}

	authReq := &storagepb.AuthRequest{}
	authReqVers, err := s.storage.Get(ctx, authReqKeyspace, authID, authReq)
	if err != nil {
		return "", err
	}

	authReq.LoggedIn = true
	authReq.Claims = claims
	authReq.ConnectorData = ident.ConnectorData

	if _, err := s.storage.Put(ctx, authReqKeyspace, authReq.Id, authReqVers, authReq); err != nil {
		return "", fmt.Errorf("failed to update auth request: %v", err)
	}

	email := claims.Email
	if !claims.EmailVerified {
		email = email + " (unverified)"
	}

	s.logger.Infof("login successful: connector %q, username=%q, email=%q, groups=%q",
		authReq.ConnectorId, claims.Username, email, claims.Groups)

	return s.absURL("/approval") + "?req=" + authReq.Id, nil
}
