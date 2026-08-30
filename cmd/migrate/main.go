// command migrate applies any pending database migrations against DATABASE_URL and exits
// it's the discrete alternative to AUTO_MIGRATE=true:
// run it once as a deploy step (a Kubernetes Job, a CI/CD release hook, a one-off `docker run`)
// before starting iam-server, then run the server itself with AUTO_MIGRATE=false
// that way replicas never race each other applying schema changes concurrently on boot, and a bad migration doesn't
// take every instance down with it.
//
// Usage:
//
//	DATABASE_URL=postgres://... /migrate
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is not set")
	}
	return postgres.Migrate(dbURL)
}
