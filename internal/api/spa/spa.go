package spa

import (
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/lusopoint/lusoiam/web"
)

// distRoot is the sub-filesystem rooted at the embedded "dist" dir, so
// we can serve files at their natural paths (index.html, assets/...)
var distRoot fs.FS = mustSub(web.DistFS, "dist")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// Register attaches /admin/ catch-all routes to mux
func Register(mux *http.ServeMux) {
	h := &handler{fs: distRoot}
	mux.Handle("GET /admin/", h)
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
}

// handler serves SPA assets and falls back to index.html for client routes
type handler struct {
	fs fs.FS
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/admin/v1/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"Not Found","status":404,"code":"not_found"}`))
		return
	}

	relPath := strings.TrimPrefix(r.URL.Path, "/admin/")
	if relPath == "" {
		relPath = "index.html"
	}

	f, err := h.fs.Open(relPath)
	if err == nil {
		defer f.Close()
		info, statErr := f.Stat()
		if statErr == nil && !info.IsDir() {
			setCacheHeaders(w, relPath)
			if strings.HasSuffix(relPath, ".webmanifest") {
				w.Header().Set("Content-Type", "application/manifest+json")
			}
			http.ServeFileFS(w, r, h.fs, relPath)
			return
		}
	}

	if !errors.Is(err, fs.ErrNotExist) && err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if isAssetPath(relPath) {
		http.NotFound(w, r)
		return
	}
	setCacheHeaders(w, "index.html")
	http.ServeFileFS(w, r, h.fs, "index.html")
}

// isAssetPath reports whether p looks like a file request (has an
// extension that isn't an SPA route segment). We deliberately keep this
// list short: the common cases are JS, CSS, fonts, images, and source maps
func isAssetPath(p string) bool {
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
// filenames under /assets/ so they can safely be cached forever
func setCacheHeaders(w http.ResponseWriter, relPath string) {
	if strings.HasPrefix(relPath, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
}
