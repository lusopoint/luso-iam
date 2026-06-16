package middleware

import "net/http"

// Middleware is the standard Go middleware signature
type Middleware func(http.Handler) http.Handler

// Chain composes middlewares around an inner handler
// The first middleware in the list is the outermost, exampe: it sees the request first and the
// response last
//
//	handler := middleware.Chain(mux, mw1, mw2, mw3)
//	request flow:  mw1 -> mw2 -> mw3 -> mux
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
