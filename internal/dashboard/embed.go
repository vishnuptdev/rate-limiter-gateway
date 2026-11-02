// Package dashboard embeds the RateGuard admin single-page application.
//
// The SPA is plain ES modules and CSS with no build step and no third-party
// code. It is written to run under the admin server's strict CSP
// (default-src 'self'; script-src 'self'; style-src 'self'): there are no
// inline scripts, no style attributes in markup and no eval.
package dashboard

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var embedded embed.FS

// FS is the dashboard's static file tree, rooted at the static directory
// (it contains index.html, css/ and js/).
var FS fs.FS

func init() {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		panic(err)
	}
	FS = sub
}
