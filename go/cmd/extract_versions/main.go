// Package main implements a tool to extract unique versions from OSV vulnerabilities zip file.
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"slices"
	"sync"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: extract_versions <zipfile> <outputfile>")
		os.Exit(1)
	}
	zipFile := os.Args[1]
	outputFile := os.Args[2]

	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		panic(err)
	}
	defer zipReader.Close()

	versionChan := make(chan string, 1000)
	var wg sync.WaitGroup

	// Worker pool
	numWorkers := runtime.NumCPU()
	fileChan := make(chan *zip.File)

	// Start workers
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				r, err := file.Open()
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					continue
				}
				bytes, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					continue
				}
				var vuln osvschema.Vulnerability
				if err := protojson.Unmarshal(bytes, &vuln); err != nil {
					fmt.Fprintln(os.Stderr, err)
					continue
				}
				for _, affected := range vuln.GetAffected() {
					for _, version := range affected.GetVersions() {
						versionChan <- version
					}
					for _, ranges := range affected.GetRanges() {
						if ranges.GetType() == osvschema.Range_GIT {
							continue
						}
						for _, event := range ranges.GetEvents() {
							if event.GetIntroduced() != "" {
								versionChan <- event.GetIntroduced()
							}
							if event.GetFixed() != "" {
								versionChan <- event.GetFixed()
							}
							if event.GetLastAffected() != "" {
								versionChan <- event.GetLastAffected()
							}
						}
					}
				}
			}
		}()
	}

	// Collector
	allVersions := make(map[string]struct{})
	doneChan := make(chan struct{})
	go func() {
		for v := range versionChan {
			allVersions[v] = struct{}{}
		}
		close(doneChan)
	}()

	// Feed files to workers
	for _, file := range zipReader.File {
		fileChan <- file
	}
	close(fileChan)

	// Wait for workers to finish
	wg.Wait()
	close(versionChan)

	// Wait for collector to finish
	<-doneChan

	// Sort versions
	vers := slices.Sorted(maps.Keys(allVersions))

	// Write to output file
	f, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	for _, v := range vers {
		if _, err := fmt.Fprintln(f, v); err != nil {
			panic(err)
		}
	}

	fmt.Printf("Successfully extracted %d unique versions to %s\n", len(vers), outputFile)
}
