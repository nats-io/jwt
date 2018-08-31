#!/bin/bash -e
# Run from directory above via ./scripts/cov.sh

rm -rf ./cov
mkdir cov
go test -v -race -covermode=atomic -coverprofile=./cov/coverage.out -coverpkg=github.com/nats-io/jwt .
gocovmerge ./cov/*.out > coverage.out
rm -rf ./cov

# If we have an arg, assume travis run and push to coveralls. Otherwise launch browser results
if [[ -n $1 ]]; then
    $HOME/gopath/bin/goveralls -coverprofile=coverage.out -service travis-ci
    rm -rf ./coverage.out
else
    go tool cover -html=coverage.out
fi