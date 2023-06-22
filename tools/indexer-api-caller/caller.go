package main

import (
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	repoDir   = flag.String("lib", "", "library directory")
	repoDir2  = flag.String("lib2", "", "specify another directory to compare file hashes to the first")
	searchDir = flag.String("dir", "", "third party directory containing multiple libraries")
	fileExts  = []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}
)

type Hash = [16]byte

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string `datastore:"path,noindex"`
	Hash Hash   `datastore:"hash"`
}

func main() {
	flag.Parse()

	if *repoDir != "" {
		aRes, err := buildGit(*repoDir)
		if err != nil {
			log.Fatal(err)
		}
		if *repoDir2 != "" {
			bRes, err := buildGit(*repoDir2)
			if err != nil {
				log.Fatal(err)
			}

			matchCount := 0

			a := fileResToMap(aRes)
			for _, fr := range bRes {
				_, ok := a[fr.Hash]
				if ok {
					matchCount += 1
				}
			}

			log.Printf("Number of matched file hashes: %d", matchCount)
		}
	}

	if *searchDir != "" {
		entries, err := os.ReadDir(*searchDir)
		if err != nil {
			log.Panicf("Failed to read dir: %v", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				path := filepath.Join(*searchDir, entry.Name())
				log.Printf("Scanning %s", path)
				_, err := buildGit(path)
				if err != nil {
					log.Printf("Error when scanning %v: %v", entry.Name(), err)
				}
			}
		}
	}
}

func fileResToMap(input []*FileResult) map[Hash]bool {
	a := map[Hash]bool{}
	for _, fr := range input {
		a[fr.Hash] = true
	}
	return a
}

func buildGit(repoDir string) ([]*FileResult, error) {
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
					Hash: hash,
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed during file walk: %v", err)
	}

	log.Printf("Hashed %v files", len(fileResults))

	b := strings.Builder{}
	b.WriteString(fmt.Sprintf(`{"name":"%s", "file_hashes": [`, filepath.Base(repoDir)))

	for i, fr := range fileResults {
		if i == len(fileResults)-1 {
			fmt.Fprintf(&b, "{\"hash\": \"%s\", \"file_path\": \"%s\"}", base64.StdEncoding.EncodeToString(fr.Hash[:]), fr.Path)
		} else {
			fmt.Fprintf(&b, "{\"hash\": \"%s\", \"file_path\": \"%s\"},", base64.StdEncoding.EncodeToString(fr.Hash[:]), fr.Path)
		}
	}
	b.WriteString("]}")

	res, err := http.Post("https://api.osv.dev/v1experimental/determineversion", "application/json", strings.NewReader(b.String()))
	if err != nil {
		return nil, fmt.Errorf("Failed to make request: %v", err)
	}

	output, err := io.ReadAll(res.Body)

	if err != nil {
		log.Panicf("%s: %s", err.Error(), string(output))
	}

	log.Println(string(output))
	return fileResults, nil
}
