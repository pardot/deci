package signer

import (
	"context"
	"errors"

	jose "gopkg.in/square/go-jose.v2"
)

// StaticSigner uses a fixed set of keys to manage signing operations
type StaticSigner struct {
	signingKey       jose.SigningKey
	verificationKeys []jose.JSONWebKey
}

// NewStatic returns a StaticSigner with the provided keys
func NewStatic(signingKey jose.SigningKey, verificationKeys []jose.JSONWebKey) *StaticSigner {
	return &StaticSigner{
		signingKey:       signingKey,
		verificationKeys: verificationKeys,
	}
}

// PublicKeys returns a keyset of all valid signer public keys considered
// valid for signed tokens
func (s *StaticSigner) PublicKeys(_ context.Context) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{
		Keys: s.verificationKeys,
	}, nil
}

// SignerAlg returns the algorithm the signer uses
func (s *StaticSigner) SignerAlg(_ context.Context) (jose.SignatureAlgorithm, error) {
	return jose.RS256, nil
}

// Sign the provided data
func (s *StaticSigner) Sign(_ context.Context, data []byte) (signed []byte, err error) {
	signer, err := jose.NewSigner(s.signingKey, nil)
	if err != nil {
		return nil, err
	}

	jws, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}

	ser, err := jws.CompactSerialize()
	return []byte(ser), err
}

// VerifySignature verifies the signature given token against the current signers
func (s *StaticSigner) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}

	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	for _, key := range s.verificationKeys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(key); err == nil {
				return payload, nil
			}
		}
	}

	return nil, errors.New("failed to verify id token signature")
}
