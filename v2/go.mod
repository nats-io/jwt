module github.com/nats-io/jwt/v2

require (
	github.com/nats-io/jwt v0.3.2
	github.com/nats-io/nkeys v0.1.4
	github.com/stretchr/testify v1.5.1
)

replace github.com/nats-io/jwt v0.3.2 => ../

go 1.14
