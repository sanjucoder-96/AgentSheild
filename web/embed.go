// Package web embeds the built dashboard (web/dist) into the gateway binary,
// so running the gateway needs no Node.js. Rebuild with: cd web && npm run build
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the dashboard files, or nil if the build is missing.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
