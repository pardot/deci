.PHONY: all build test proto gobin packr

gopath=$(shell go env GOPATH)

all: proto packr build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: $(gopath)/bin/gobin
	$(gopath)/bin/gobin -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run ./...

packr: oidcserver/oidcserver-packr.go

oidcserver/oidcserver-packr.go: $(gopath)/bin/gobin oidcserver/web
	cd oidcserver && gobin -m -run github.com/gobuffalo/packr/v2/packr2 clean
	cd oidcserver && gobin -m -run github.com/gobuffalo/packr/v2/packr2

proto: proto/deci/storage/v1beta1/storage.pb.go proto/deci/storage/v2beta1/storage.pb.go

proto/deci/storage/v1beta1/storage.pb.go: proto/deci/storage/v1beta1/storage.proto
	protoc -I proto --go_out=paths=source_relative:proto deci/storage/v1beta1/storage.proto

proto/deci/storage/v2beta1/storage.pb.go: proto/deci/storage/v2beta1/storage.proto
	protoc -I proto --go_out=paths=source_relative:proto deci/storage/v2beta1/storage.proto

$(gopath)/bin/gobin:
	(cd /tmp && GO111MODULE=on go get -u github.com/myitcv/gobin@latest)
