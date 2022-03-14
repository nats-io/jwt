#!/bin/bash -e
# Run from directory above via ./scripts/test.sh

gofmt -s -w *.go
goimports -w *.go
go vet ./...
go test -v
go test -v --race

cd v2 && (
  gofmt -s -w *.go
  goimports -w *.go
  go vet -modfile=go_test.mod ./...
  go test github.com/nats-io/jwt/v2 -v
  go test github.com/nats-io/jwt/v2 -v --race
  go test -modfile=go_test.mod github.com/nats-io/jwt/v2/test -v
  go test -modfile=go_test.mod github.com/nats-io/jwt/v2/test -v --race
)

staticcheck ./...
