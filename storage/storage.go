package storage

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"io"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
)

// Storage is an interface used by the service to maintain
// state.
type Storage interface {
	// Get returns the given item. If the item doesn't exist, an IsNotFoundErr
	// will be returned. The returned version should be submitted with any
	// updates to the returned object
	Get(ctx context.Context, keyspace, key string, into proto.Message) (version int64, err error)
	// Put stores the provided item. If this is an update to an existing object
	// it's version should be included; for new objects the version should be 0. If
	// the update fails because of a version conflict, an IsConflictErr will be
	// returned. Any existing expiration set on the object should be preserved.
	Put(ctx context.Context, keyspace, key string, version int64, obj proto.Message) (newVersion int64, err error)
	// PutWithExpiry is a Put, with a time that the item should no longer
	// be accessible. This doesn't guarantee that the data will be deleted at
	// the time, but Get should not return it.
	PutWithExpiry(ctx context.Context, keyspace, key string, version int64, obj proto.Message, expires time.Time) (newVersion int64, err error)
	// List retrieves all keys in the given keyspace.
	List(ctx context.Context, keyspace string) (keys []string, err error)
	// Delete removes the item. If the item doesn't exist, an IsNotFoundErr will
	// be returned.
	Delete(ctx context.Context, keyspace, key string) error
}

type errNotFound interface {
	NotFoundErr()
}

// IsNotFoundErr checks to see if the passed error is because the item was not
// found, as opposed to an actual error state. Errors comply to this if they
// have an `NotFoundErr()` method.
func IsNotFoundErr(err error) bool {
	_, ok := err.(errNotFound)
	return ok
}

type errConflict interface {
	ConflictErr()
}

// IsConflictErr checks to see if the passed error occurred because of a version
// conflict. Errors comply to this if they have a `ConflictErr()` method
func IsConflictErr(err error) bool {
	_, ok := err.(errConflict)
	return ok
}

// Kubernetes only allows lower case letters for names.
//
// TODO(ericchiang): refactor ID creation onto the storage.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

// NewID returns a random string which can be used as an ID for objects.
func NewID() string {
	buff := make([]byte, 16) // 128 bit random ID.
	if _, err := io.ReadFull(rand.Reader, buff); err != nil {
		panic(err)
	}
	// Avoid the identifier to begin with number and trim padding
	return string(buff[0]%26+'a') + strings.TrimRight(encoding.EncodeToString(buff[1:]), "=")
}
