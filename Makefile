.PHONY: test cover

build:
	go build

test:
	go test -v

cover:
	 go test -v -covermode=count -coverprofile=coverage.out
	 go tool cover -html=coverage.out