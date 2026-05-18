// Package web exposes the compiled React admin SPA as an embedded
// filesystem. It exists purely as a vehicle for the //go:embed directive
// — the embed can only reach files within its own package directory, so
// the embed declaration must live next to web/dist itself.
//
// Use:
//
//	import "github.com/iam-server/iam/web"
//	fs.Sub(web.DistFS, "dist")
//
// The dist directory ships with a stub index.html so the binary builds
// before `make web-build` is ever run; the stub renders a short
// instruction page telling the operator to compile the SPA.
package web

import "embed"

// DistFS is the embedded React build output (web/dist tree).
//
//go:embed all:dist
var DistFS embed.FS
