.PHONY: all build test proto gobin packr

gopath=$(shell go env GOPATH)

all: proto packr build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: bin/golangci-lint-1.23.8
	./bin/golangci-lint-1.23.8 run ./...

packr: oidcserver/oidcserver-packr.go

oidcserver/oidcserver-packr.go: $(gopath)/bin/gobin oidcserver/web
	cd oidcserver && gobin -m -run github.com/gobuffalo/packr/v2/packr2 clean
	cd oidcserver && gobin -m -run github.com/gobuffalo/packr/v2/packr2

proto: proto/deci/storage/v1beta1/storage.pb.go proto/deci/storage/v2beta1/storage.pb.go

proto/deci/storage/v1beta1/storage.pb.go: proto/deci/storage/v1beta1/storage.proto
	protoc -I proto --go_out=paths=source_relative:proto deci/storage/v1beta1/storage.proto

proto/deci/storage/v2beta1/storage.pb.go: proto/deci/storage/v2beta1/storage.proto
	protoc -I proto --go_out=paths=source_relative:proto deci/storage/v2beta1/storage.proto

bin/golangci-lint-1.23.8:
	./hack/fetch-golangci-lint.sh
