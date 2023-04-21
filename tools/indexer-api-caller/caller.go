package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	repoDir = flag.String("repo", "", "repo directory")
)

type Hash = []byte

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string `datastore:"path,noindex"`
	Hash Hash   `datastore:"hash"`
}

func main() {
	flag.Parse()
	buildGit(*repoDir)
}

func buildGit(repoDir string) error {
	fileExts := []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}

	var fileResults []*FileResult
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		for _, ext := range fileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				hash := md5.Sum(buf)
				fileResults = append(fileResults, &FileResult{
					Path: strings.ReplaceAll(p, repoDir, ""),
					Hash: hash[:],
				})
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed during file walk: %v", err)
	}

	log.Printf("%v", len(fileResults))

	b := strings.Builder{}
	b.WriteString(`{"query": {"name":"protobuf", "file_hashes": [`)

	for i, fr := range fileResults {
		if i == len(fileResults)-1 {
			fmt.Fprintf(&b, "{\"hash\": \"%s\"}", base64.StdEncoding.EncodeToString(fr.Hash))
		} else {
			fmt.Fprintf(&b, "{\"hash\": \"%s\"},", base64.StdEncoding.EncodeToString(fr.Hash))
		}
	}
	b.WriteString("]}}")

	// TODO: Use proper grpc library calls here
	cmd := exec.Command("bash")
	cmd.Args = append(cmd.Args, "-c", `grpcurl -plaintext -d @ -protoset api_descriptor.pb 127.0.0.1:8000 osv.v1.OSV/DetermineVersion`)

	buffer := bytes.Buffer{}
	_, err := buffer.Write([]byte(b.String()))
	if err != nil {
		log.Panicln(err)
	}

	cmd.Stdin = &buffer
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Panicf("%s: %s", err.Error(), string(output))
	}

	log.Println(string(output))
	return nil
}
