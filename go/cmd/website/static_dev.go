//go:build !embedstatic

package main

import (
	"io/fs"
	"os"
)

func getStaticFS(dir string) (fs.FS, error) {
	return os.DirFS(dir), nil
}

func getDocsFS(dir string) (fs.FS, error) {
	return os.DirFS(dir), nil
}
