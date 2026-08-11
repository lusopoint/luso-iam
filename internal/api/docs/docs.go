package docs

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/docs.html
var templatesFS embed.FS

var funcs = template.FuncMap{
	"lower": strings.ToLower,
	// slug turns a section title into a stable anchor id
	"slug": func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		var b strings.Builder
		dash := false
		for _, r := range s {
			switch {
			case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
				b.WriteRune(r)
				dash = false
			default:
				if !dash && b.Len() > 0 {
					b.WriteByte('-')
					dash = true
				}
			}
		}
		return strings.TrimRight(b.String(), "-")
	},
}

var page = template.Must(
	template.New("docs.html").Funcs(funcs).ParseFS(templatesFS, "templates/docs.html"),
)

type Config struct {
	// Enabled mirrors DOCS_ENABLED, when false returns 404
	Enabled bool
}

type Handler struct {
	enabled bool
	content Content
}

func New(cfg Config) *Handler {
	return &Handler{enabled: cfg.Enabled, content: Build()}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /docs", h.serve)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if err := page.Execute(w, h.content); err != nil {
		// avoid leaking template internals to the client
		return
	}
}
