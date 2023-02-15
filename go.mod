module github.com/pardot/deci

// +heroku goVersion go1.13
// +heroku install ./cmd/...

go 1.13

require (
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/felixge/httpsnoop v1.0.0
	github.com/gobuffalo/packr/v2 v2.5.1
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.5
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.6.2
	github.com/kylelemons/godebug v0.0.0-20170820004349-d65d576e9348
	github.com/lib/pq v1.2.0
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus/client_golang v1.11.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/pflag v1.0.5 // indirect
	go.etcd.io/bbolt v1.3.3
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/tools v0.0.0-20191010075000-0337d82405ff // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/square/go-jose.v2 v2.4.0
)
