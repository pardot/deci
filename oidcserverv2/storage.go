package oidcserverv2

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	storagepb "github.com/pardot/deci/proto/deci/storage/v2beta1"
	"github.com/pardot/deci/storage"
	"github.com/pardot/oidc/core"
)

const (
	sessKeyspace = "deci-v2-session"
)

var _ core.SessionManager = (*sessionMgr)(nil)

type sessionMgr struct {
	storage storage.Storage
}

func (s *sessionMgr) GetSession(ctx context.Context, sessionID string, into core.Session) (found bool, err error) {
	sess := &storagepb.Session{}

	_, err = s.storage.Get(ctx, sessKeyspace, sessionID, sess)
	if err != nil {
		if storage.IsNotFoundErr(err) {
			return false, nil
		}
		return false, err
	}

	if err := ptypes.UnmarshalAny(sess.OidcSession, into); err != nil {
		return false, fmt.Errorf("failed to unmarshal OIDC session: %v", err)
	}

	return true, nil
}

func (s *sessionMgr) PutSession(ctx context.Context, oidcsess core.Session) error {
	exp, err := ptypes.Timestamp(oidcsess.GetExpiresAt())
	if err != nil {
		return err
	}

	sess := &storagepb.Session{}

	sessVer, err := s.storage.Get(ctx, sessKeyspace, oidcsess.GetId(), sess)
	if err != nil && !storage.IsNotFoundErr(err) { // ignore is not found, will just create a new session
		return err
	}

	oany, err := ptypes.MarshalAny(oidcsess)
	if err != nil {
		return fmt.Errorf("failed to marshal any: %v", err)
	}

	sess.OidcSession = oany

	if _, err := s.storage.PutWithExpiry(ctx, sessKeyspace, oidcsess.GetId(), sessVer, sess, exp); err != nil {
		return err
	}

	return nil
}

func (s *sessionMgr) DeleteSession(ctx context.Context, sessionID string) error {
	err := s.storage.Delete(ctx, sessKeyspace, sessionID)
	if err != nil && !storage.IsNotFoundErr(err) {
		return err
	}

	return nil
}
