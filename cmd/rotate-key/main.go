// this service basically generates a fresh RSA 2048 signing key inside a keys directory
// naming is done with a sortable timestamp prefix so that the
// IAM server multi key loader picks it up as the new primary on
// the next restart
//
// for now we need to follow the steps:
// - run the program to drop a new key file into the directory
// - restart the IAM server, it loads the new key as primary
//   the previous primary becomes retiring (still in JWKS
//   for verifying not yet expired tokens)
// - after max token TTL passes (normally 1h), we should
//   delete the old key file and restart again to clear it from the JWKS
// TODO: the server reads the key directory once at startup
// a "rotate without restart" would required either a signal handler
// or a filesystem watcher

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", "", "directory to write the new key into (required)")
	bits := flag.Int("bits", 2048, "RSA key size in bits (2048 or 4096)")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: rotate-key -dir /path/to/keys")
		os.Exit(2)
	}
	if *bits != 2048 && *bits != 4096 {
		fmt.Fprintln(os.Stderr, "error: -bits must be 2048 or 4096 (got %d)\n", *bits)
		os.Exit(2)
	}

	info, err := os.Stat(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "hint: create the directory first, then move your existing signing.pem")
		fmt.Fprintln(os.Stderr, "      into it, then run rotate-key. The IAM server's SIGNING_KEY_PATH")
		fmt.Fprintln(os.Stderr, "      must point at the directory (not a single file) to enable rotation.")
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is a file, not a directory.\n\n", *dir)
		fmt.Fprintln(os.Stderr, "To enable rotation, migrate the single-file setup:")
		fmt.Fprintln(os.Stderr, "   mkdir -p /etc/iam/keys")
		fmt.Fprintf(os.Stderr, "   mv %s /etc/iam/keys/20250101T000000-signing.pem\n", *dir)
		fmt.Fprintln(os.Stderr, "   # update SIGNING_KEY_PATH to /etc/iam/keys/")
		fmt.Fprintln(os.Stderr, "   # restart the server, then re-run rotate-key with -dir /etc/iam/keys")
		os.Exit(1)
	}

	// Generate the key.
	fmt.Printf("generating RSA-%d key...\n", *bits)
	key, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: generate key: %v\n", err)
		os.Exit(1)
	}

	// PKCS8 is the recent PEM format
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal key: %v\n", err)
		os.Exit(1)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	// sort the loader uses then naturally orders newest-last
	name := fmt.Sprintf("%s-signing.pem", time.Now().UTC().Format("20060102T150405Z"))
	full := filepath.Join(*dir, name)

	// tmp file + rename so we don't leave a half written key on disk if the process
	// dies while writting
	// O_EXCL will overwrite the file with the same name
	tmp := full + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create tmp file: %v\n", err)
		os.Exit(1)
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "error: write tmp file: %v\n", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "error: close tmp file: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "error: rename tmp file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nnew signing key written:\n  %s\n", full)
	fmt.Println("")
	fmt.Println("next steps:")
	fmt.Println("  1. restart the IAM server (it loads keys at startup)")
	fmt.Println("     - the new key becomes primary; the previous primary becomes retiring")
	fmt.Println("     - both keys remain in /.well-known/jwks.json so existing tokens still verify")
	fmt.Println("  2. wait at least max-access-token-TTL (default ~1 hour)")
	fmt.Println("  3. delete the OLDEST *.pem files from this directory")
	fmt.Println("  4. restart the IAM server again to clear retired keys from the JWKS")
}
