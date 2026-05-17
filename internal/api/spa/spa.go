// Package spa serves the React admin SPA from embedded static assets.
//
// The compiled output of `npm run build` (in ../../../web/) is embedded
// into the binary via the sibling `web` package and exposed here.
// At runtime this package:
//
//  1. Serves static assets under /admin/assets/* with long-lived caching.
//  2. Serves the SPA shell (index.html) for any non-asset path under
//     /admin/, so client-side routing works without server changes.
//  3. Returns a JSON 404 for anything under /admin/v1/ that wasn't
//     matched by an admin API route — otherwise unknown API calls would
//     return HTML and confuse the SPA's fetch error handling.
//
// A stub web/dist/index.html ships in the repo so the binary builds
// before `make web-build` is ever run; it tells the operator how to
// finish the setup.
package spa

import (
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/lusopoint/lusoiam/web"
)

// distRoot is the sub-filesystem rooted at the embedded "dist" dir, so
// we can serve files at their natural paths (index.html, assets/...).
var distRoot fs.FS = mustSub(web.DistFS, "dist")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		// Compile-time guarantee: the dist dir is always present in the
		// repo (with at least a stub index.html). A failure here is a
		// programmer error, not a runtime condition.
		panic(err)
	}
	return sub
}

// Register attaches /admin/ catch-all routes to mux.
//
// Specific API patterns (e.g. GET /admin/v1/users) registered elsewhere
// take precedence — Go 1.22 mux resolves by specificity — so this handler
// only sees requests that no API route claimed.
func Register(mux *http.ServeMux) {
	h := &handler{fs: distRoot}
	// Trailing slash is the canonical SPA root.
	mux.Handle("GET /admin/", h)
	// Bare /admin → redirect to /admin/ so client-side routes resolve.
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
}

// handler serves SPA assets and falls back to index.html for client routes.
type handler struct {
	fs fs.FS
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// API miss: any unknown /admin/v1/* path should be a JSON 404, not
	// an HTML render of index.html.
	if strings.HasPrefix(r.URL.Path, "/admin/v1/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"Not Found","status":404,"code":"not_found"}`))
		return
	}

	// Strip the /admin/ prefix to map to a file under dist/.
	relPath := strings.TrimPrefix(r.URL.Path, "/admin/")
	if relPath == "" {
		relPath = "index.html"
	}

	// Try the exact file first. If it exists, serve it with caching
	// headers appropriate to its type (fingerprinted assets vs HTML).
	f, err := h.fs.Open(relPath)
	if err == nil {
		defer f.Close()
		info, statErr := f.Stat()
		if statErr == nil && !info.IsDir() {
			setCacheHeaders(w, relPath)
			// Go's mime package doesn't ship a default mapping for
			// .webmanifest, so http.ServeFileFS falls back to sniffing
			// (usually mistakes it for text/plain). Set it explicitly
			// here — Lighthouse and Chrome both complain otherwise.
			if strings.HasSuffix(relPath, ".webmanifest") {
				w.Header().Set("Content-Type", "application/manifest+json")
			}
			http.ServeFileFS(w, r, h.fs, relPath)
			return
		}
	}

	// SPA fallback: serve index.html so the React Router can handle the
	// path on the client. Anything that doesn't look like an asset path
	// (no extension) gets the shell.
	if !errors.Is(err, fs.ErrNotExist) && err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Don't serve index.html for paths that look like missing assets —
	// it would confuse the browser more than a clean 404.
	if isAssetPath(relPath) {
		http.NotFound(w, r)
		return
	}
	setCacheHeaders(w, "index.html")
	http.ServeFileFS(w, r, h.fs, "index.html")
}

// isAssetPath reports whether p looks like a file request (has an
// extension that isn't an SPA route segment). We deliberately keep this
// list short: the common cases are JS, CSS, fonts, images, and source maps.
func isAssetPath(p string) bool {
	// A path like "users/123" has no extension — not an asset.
	// A path like "assets/index-abc.js" has an extension — asset.
	dot := strings.LastIndexByte(p, '.')
	if dot < 0 {
		return false
	}
	ext := strings.ToLower(p[dot:])
	switch ext {
	case ".js", ".mjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".json", ".txt", ".webmanifest":
		return true
	}
	return false
}

// setCacheHeaders applies a long max-age to fingerprinted assets (path
// segment "assets/") and no-store for the SPA shell. Vite emits hashed
// filenames under /assets/ so they can safely be cached forever.
func setCacheHeaders(w http.ResponseWriter, relPath string) {
	if strings.HasPrefix(relPath, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
}
