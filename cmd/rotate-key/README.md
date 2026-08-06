# Rotate Key

The command generates a fresh RSA-2048 signing key in the keys directory. It names the file with a sortable timestamp prefix. On the next restart, the IAM server's multi-key loader picks up this file as the new primary key.

Usage:

```console
# run go directly
go run ./cmd/rotate-key -dir /etc/iam/keys

# run using makefile
make rotate-key dir=/path/to/keys
```

The command writes the key file with mode `0600`. The command does not touch the running server, by design. Automatic rotation is more complex. It would need a signal handler or a filesystem watcher.

The rotation flow is:

1. Run `rotate-key` to generate a new key file in the keys directory.
2. Restart the IAM server. It loads the new key as the primary key. The previous primary becomes deprecated. A deprecated key stays in the JWKS to verify tokens that have not yet expired.
3. After the max token TTL passes (typically 1 hour), delete the deprecated key file. Then restart the IAM server to clear the key from the JWKS.
