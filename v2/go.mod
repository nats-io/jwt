module github.com/nats-io/jwt/v2

go 1.22

require github.com/nats-io/nkeys v0.4.8

retract (
	v2.7.1 // contains retractions only
	v2.7.0 // includes case insensitive changes to tags that break jetstream placement
)

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
