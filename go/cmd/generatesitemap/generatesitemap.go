// Package main runs the sitemap generator, creating sitemaps from vulnerability data in GCS.
package main

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

const (
	gcsProtoPrefix  = "all/pb/"
	sitemapURLLimit = 49999
	sitemapPrefix   = "sitemap_"
)

// SitemapEntry represents a single URL entry in the sitemap.
type SitemapEntry struct {
	XMLName      xml.Name `xml:"url"`
	Loc          string   `xml:"loc"`
	LastModified string   `xml:"lastmod"`
}

// URLSet represents the root element of a sitemap.
type URLSet struct {
	XMLName xml.Name       `xml:"urlset"`
	XMLNS   string         `xml:"xmlns,attr"`
	URLs    []SitemapEntry `xml:"url"`
}

// SitemapIndexEntry represents a single sitemap entry in the sitemap index.
type SitemapIndexEntry struct {
	XMLName      xml.Name `xml:"sitemap"`
	Loc          string   `xml:"loc"`
	LastModified string   `xml:"lastmod"`
}

// SitemapIndex represents the root element of a sitemap index.
type SitemapIndex struct {
	XMLName  xml.Name            `xml:"sitemapindex"`
	XMLNS    string              `xml:"xmlns,attr"`
	Sitemaps []SitemapIndexEntry `xml:"sitemap"`
}

// Entry holds the minimal data needed for sitemap generation.
type Entry struct {
	ID           string
	LastModified time.Time
}

func main() {
	logger.InitGlobalLogger()

	baseURL := flag.String("base-url", "https://osv.dev", "The base URL for the sitemap entries (without trailing /).")
	vulnBucketName := flag.String("osv-vulns-bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "GCS bucket to read vulnerability protobufs from.")
	outputDir := flag.String("bucket", "sitemap_output", "Output bucket or directory name. If -upload-to-gcs is true, this is a GCS bucket name; otherwise, it's a local directory.")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "If true, writes the output to a GCS bucket specified by -bucket.")
	numWorkers := flag.Int("workers", 200, "The total number of concurrent workers to use.")

	flag.Parse()

	if *vulnBucketName == "" {
		logger.Fatal("OSV_VULNERABILITIES_BUCKET must be set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.Fatal("failed to create storage client", slog.Any("err", err))
	}
	defer storageClient.Close()

	vulnClient := clients.NewGCSClient(storageClient, *vulnBucketName)

	var outClient clients.CloudStorage
	if *uploadToGCS {
		outClient = clients.NewGCSClient(storageClient, *outputDir)
	} else {
		if err := os.MkdirAll(*outputDir, 0755); err != nil {
			logger.Fatal("failed to create output directory", slog.Any("err", err))
		}
	}

	// Channel for GCS paths
	gcsPathCh := make(chan string)
	// Channel for parsed entries
	entryCh := make(chan *osvschema.Vulnerability)

	// Start listing objects for workers to consume
	go func() {
		defer close(gcsPathCh)
		if err := listObjects(ctx, vulnClient, gcsPathCh); err != nil {
			logger.Fatal("failed to list objects", slog.Any("err", err))
		}
	}()

	var wg sync.WaitGroup
	// Start workers
	for range *numWorkers {
		wg.Go(func() { downloader(ctx, vulnClient, gcsPathCh, entryCh) })
	}

	// Aggregate entries by ecosystem
	ecosystemEntries := make(map[string][]Entry)

	// Process entries as they come in
	go func() {
		wg.Wait()
		close(entryCh)
	}()

	count := 0
	for vuln := range entryCh {
		count++
		lastMod := time.Unix(0, 0).UTC()
		if vuln.GetModified() != nil {
			lastMod = vuln.GetModified().AsTime().UTC()
		}

		// Collect ecosystems
		ecosystems := make(map[string]struct{})
		for _, affected := range vuln.GetAffected() {
			if affected.GetPackage() != nil && affected.GetPackage().GetEcosystem() != "" {
				eco, _, _ := strings.Cut(affected.GetPackage().GetEcosystem(), ":")
				ecosystems[eco] = struct{}{}
			}
			// Check for GIT ranges
			for _, r := range affected.GetRanges() {
				if r.GetType() == osvschema.Range_GIT {
					ecosystems["GIT"] = struct{}{}
				}
			}
		}
		if len(ecosystems) == 0 {
			ecosystems["[EMPTY]"] = struct{}{}
		}

		entry := Entry{
			ID:           vuln.GetId(),
			LastModified: lastMod,
		}

		for eco := range ecosystems {
			ecosystemEntries[eco] = append(ecosystemEntries[eco], entry)
		}
	}

	logger.Info("processed vulnerabilities", slog.Int("count", count))

	// Generate sitemaps
	if err := generateSitemaps(ctx, outClient, *outputDir, *baseURL, ecosystemEntries); err != nil {
		logger.Fatal("failed to generate sitemaps", slog.Any("err", err))
	}

	logger.Info("sitemap generation complete")
}

func listObjects(ctx context.Context, client clients.CloudStorage, outCh chan<- string) error {
	prevPrefix := ""
	for name, err := range client.Objects(ctx, gcsProtoPrefix) {
		if err != nil {
			return err
		}
		// Only log when we see a new ID prefix (i.e. roughly once per data source)
		prefix := filepath.Base(name)
		prefix, _, _ = strings.Cut(prefix, "-")
		if prefix != prevPrefix {
			logger.Info("iterating vulnerabilities", slog.String("now_at", name))
			prevPrefix = prefix
		}
		select {
		case outCh <- name:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func downloader(ctx context.Context, client clients.CloudStorage, inCh <-chan string, outCh chan<- *osvschema.Vulnerability) {
	for path := range inCh {
		// Download and parse
		content, err := client.ReadObject(ctx, path)
		if err != nil {
			logger.Error("failed to read content", slog.String("path", path), slog.Any("err", err))
			continue
		}

		var vuln osvschema.Vulnerability
		if err := proto.Unmarshal(content, &vuln); err != nil {
			logger.Error("failed to unmarshal protobuf", slog.String("path", path), slog.Any("err", err))
			continue
		}

		select {
		case outCh <- &vuln:
		case <-ctx.Done():
			return
		}
	}
}

func generateSitemaps(ctx context.Context, client clients.CloudStorage, outputDir, baseURL string, entries map[string][]Entry) error {
	var sitemapIndexEntries []SitemapIndexEntry

	// Sort ecosystems for deterministic output
	ecosystems := make([]string, 0, len(entries))
	for eco := range entries {
		ecosystems = append(ecosystems, eco)
	}
	sort.Strings(ecosystems)

	for _, eco := range ecosystems {
		vulns := entries[eco]
		// Sort by LastModified ascending (oldest first)
		sort.Slice(vulns, func(i, j int) bool {
			return vulns[i].LastModified.Before(vulns[j].LastModified)
		})

		// Split into chunks
		chunks := chunkEntries(vulns, sitemapURLLimit)

		sanitizedEco := sanitizeEcosystem(eco)

		for i, chunk := range chunks {
			filename := fmt.Sprintf("%s%s.xml", sitemapPrefix, sanitizedEco)
			if len(chunks) > 1 {
				filename = fmt.Sprintf("%s%s_%d.xml", sitemapPrefix, sanitizedEco, i+1)
			}

			path := filename
			if client == nil {
				path = filepath.Join(outputDir, filename)
			}

			if err := writeSitemap(ctx, client, path, baseURL, chunk); err != nil {
				return err
			}

			// Add to index
			chunkLastMod := time.Unix(0, 0).UTC()
			if len(chunk) > 0 {
				// Since we sort by oldest first, the last item is the newest
				chunkLastMod = chunk[len(chunk)-1].LastModified
			}

			sitemapIndexEntries = append(sitemapIndexEntries, SitemapIndexEntry{
				Loc:          fmt.Sprintf("%s/%s", baseURL, filename),
				LastModified: chunkLastMod.Format(time.RFC3339),
			})
		}
	}

	// Write sitemap index
	filename := sitemapPrefix + "index.xml"
	path := filename
	if client == nil {
		path = filepath.Join(outputDir, filename)
	}

	return writeSitemapIndex(ctx, client, path, sitemapIndexEntries)
}

func chunkEntries(entries []Entry, limit int) [][]Entry {
	var chunks [][]Entry
	for i := 0; i < len(entries); i += limit {
		end := min(i+limit, len(entries))
		chunks = append(chunks, entries[i:end])
	}

	return chunks
}

func sanitizeEcosystem(eco string) string {
	s := strings.TrimSpace(eco)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ".", "__")

	return s
}

func writeSitemap(ctx context.Context, client clients.CloudStorage, path, baseURL string, entries []Entry) error {
	urlSet := URLSet{
		XMLNS: "http://www.sitemaps.org/schemas/sitemap/0.9",
	}

	for _, e := range entries {
		urlSet.URLs = append(urlSet.URLs, SitemapEntry{
			Loc:          fmt.Sprintf("%s/vulnerability/%s", baseURL, e.ID),
			LastModified: e.LastModified.Format(time.RFC3339),
		})
	}

	return writeSitemapFile(ctx, client, path, urlSet)
}

func writeSitemapIndex(ctx context.Context, client clients.CloudStorage, path string, entries []SitemapIndexEntry) error {
	index := SitemapIndex{
		XMLNS:    "http://www.sitemaps.org/schemas/sitemap/0.9",
		Sitemaps: entries,
	}

	return writeSitemapFile(ctx, client, path, index)
}

// crc32Table uses the Castagnoli CRC32 polynomial for checksums to match GCS.
var crc32Table = crc32.MakeTable(crc32.Castagnoli)

func writeSitemapFile(ctx context.Context, client clients.CloudStorage, path string, v any) error {
	data, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)

	if client == nil {
		return os.WriteFile(path, data, 0600)
	}

	attrs, err := client.ReadObjectAttrs(ctx, path)
	if err == nil {
		checksum := crc32.Checksum(data, crc32Table)
		if checksum == attrs.CRC32C {
			logger.Info("skipping upload since checksum is unchanged",
				slog.String("path", path), slog.Any("crc32c", checksum))

			return nil
		}
	} else if !errors.Is(err, clients.ErrNotFound) {
		return fmt.Errorf("failed getting checksum: %w", err)
	}

	return client.WriteObject(ctx, path, data, nil)
}
