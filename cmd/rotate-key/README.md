## Rotate Key

Rotates a fresh RSA-2048 signing key inside the keys directory, naming it with a sortable timestamp prefix so that the IAM server's multi-key loader picks it up as the new primary on next restart

Usage:

```console
# run go directly
go run ./cmd/rotate-key -dir /etc/iam/keys

# run using makefile
make rotate-key dir=/path/to/keys
```

The key files is written 0600, the script intentionally does not touch the running server. Basically auto rotation is a bit more complex (we would have to create a signal handler or filesystem watcher)

So the flow would be:

1. Run the `rote-key` to generate a new key file into the signature files directory.
2. Restart the IAM server. It will load the new key as primary, the previous primary becomes deprecated (basically still in JWKS for verifying not-yet-expired tokens).
3. After max-token-TTL passes (typically 1 hour), then delete the deprecated key file and restart IAM server to clear it from the JWKS.
