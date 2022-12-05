module github.com/nats-io/jwt/v2

go 1.18

require (
	github.com/nats-io/jwt v1.2.2
	github.com/nats-io/nkeys v0.3.0
)

require golang.org/x/crypto v0.0.0-20210314154223-e6e6c4f2bb5b // indirect

replace github.com/nats-io/jwt v1.2.2 => ../
