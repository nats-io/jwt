.PHONY: test cover

build:
	go build

test:
	./scripts/test.sh

fmt:
	gofmt -w -s *.go
	go mod tidy
	cd v2/
	gofmt -w -s *.go
	go mod tidy

cover:
	 go test -v -covermode=count -coverprofile=coverage.out
	 go tool cover -html=coverage.out
