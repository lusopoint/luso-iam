package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path"
)

// package web holds the shared components for every server rendered page:
// the base HTML layout, the design tokens, and the stylesheet

//go:embed base.html
var layoutFS embed.FS

//go:embed static
var staticFS embed.FS

// Pages parses each page template in pagesFS against the shared base layout and
// returns them keyed by file name ("login.html", "consent.html", ...)
func Pages(pagesFS fs.FS, glob string) (map[string]*template.Template, error) {
	base, err := template.New("base.html").ParseFS(layoutFS, "base.html")
	if err != nil {
		return nil, err
	}

	names, err := fs.Glob(pagesFS, glob)
	if err != nil {
		return nil, err
	}

	pages := make(map[string]*template.Template, len(names))
	for _, name := range names {
		// clone so each page starts from a pristine base: its "content",
		// "title" and "scripts" blocks override the defaults declared in
		// base.html without leaking into the next page
		set, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := set.ParseFS(pagesFS, name); err != nil {
			return nil, err
		}
		pages[path.Base(name)] = set
	}
	return pages, nil
}

// MustPages is Pages, panicking on error, called from package level vars so a
// malformed template fails at startup rather than on a users sign-in attempt
func MustPages(pagesFS fs.FS, glob string) map[string]*template.Template {
	pages, err := Pages(pagesFS, glob)
	if err != nil {
		panic("web: parsing templates: " + err.Error())
	}
	return pages
}

// Render writes the named page
func Render(w http.ResponseWriter, pages map[string]*template.Template, name string, status int, data any) {
	tmpl, ok := pages[name]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = tmpl.ExecuteTemplate(w, "base", data)
}

// Register mounts the shared static assets (tokens.css, auth.css, webauthn.js)
func Register(mux *http.ServeMux) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("web: static sub-FS: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(sub))

	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheControl(fileServer)))
}

// cacheControl sets a short cache lifetime on the shared assets
func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		next.ServeHTTP(w, r)
	})
}
