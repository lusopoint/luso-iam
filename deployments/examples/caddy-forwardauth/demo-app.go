package main

import (
	"fmt"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The HTML body contains backticks (for code), so we can't use a
		// raw-string literal — string-concat instead.
		fmt.Fprint(w, "<!doctype html>\n"+
			"<html><head><title>demo-app</title>\n"+
			"<style>\n"+
			"  body{font:16px/1.5 -apple-system,sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem}\n"+
			"  h1{font-size:1.4rem;margin:0 0 1rem}\n"+
			"  table{border-collapse:collapse;width:100%}\n"+
			"  th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid #eee;font-family:monospace;font-size:.9rem}\n"+
			"  th{background:#f5f5f5;width:14rem}\n"+
			"  .muted{color:#888}\n"+
			"</style></head>\n"+
			"<body>\n"+
			"  <h1>demo-app &mdash; what Caddy passed us</h1>\n"+
			"  <p class=\"muted\">These headers were set by /proxy/verify on the IAM server, "+
			"forwarded by Caddy's forward_auth directive. Your app reads them in "+
			"exactly the same way it would read any HTTP header.</p>\n"+
			"  <table>")

		// Show all X-Auth-* headers, in canonical order.
		for _, h := range []string{
			"X-Auth-Sub",
			"X-Auth-User",
			"X-Auth-Username",
			"X-Auth-Email",
			"X-Auth-Name",
			"X-Auth-Groups",
		} {
			v := r.Header.Get(h)
			if v == "" {
				v = "<span class=\"muted\">(empty)</span>"
			}
			fmt.Fprintf(w, "<tr><th>%s</th><td>%s</td></tr>", h, v)
		}

		fmt.Fprint(w, "</table><h2>Full request</h2><pre>")
		fmt.Fprintf(w, "%s %s\n\n", r.Method, r.URL.Path)
		for k, vs := range r.Header {
			// Hide cookies — they're long and noisy.
			if strings.EqualFold(k, "Cookie") {
				continue
			}
			for _, v := range vs {
				fmt.Fprintf(w, "%s: %s\n", k, v)
			}
		}
		fmt.Fprint(w, "</pre></body></html>")
	})

	addr := ":3000"
	fmt.Println("demo-app listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}
