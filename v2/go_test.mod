module github.com/nats-io/jwt/v2

go 1.18

require (
	github.com/nats-io/jwt v1.2.2
	github.com/nats-io/nkeys v0.3.1-0.20221205184623-5d8a6730c42c
)

require (
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
)

replace github.com/nats-io/jwt v1.2.2 => ../
