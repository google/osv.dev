//go:build embedstatic

package main

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var embeddedDist embed.FS

//go:embed docs/*
var embeddedDocs embed.FS

func getStaticFS(_ string) (fs.FS, error) {
	return fs.Sub(embeddedDist, "dist")
}

func getDocsFS(_ string) (fs.FS, error) {
	return fs.Sub(embeddedDocs, "docs")
}
