// package main combines CVEs and security advisories into OSV records.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/conversion/writer"
	"github.com/google/osv/vulnfeeds/gcs-tools"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultOSVOutputPath = "osv-output"
	defaultCVE5Path      = "cve5"
	defaultNVDOSVPath    = "nvd"
)

// CVEWorkItem represents a unit of work for a single CVE.
type CVEWorkItem struct {
	ID       models.CVEID
	CVE5Path string
	NVDPath  string
}

func cveIDFromPath(p string) models.CVEID {
	base := filepath.Base(p)
	id := strings.TrimSuffix(base, ".json")
	if strings.HasPrefix(id, "CVE-") {
		return models.CVEID(id)
	}

	return ""
}

func listObjects(ctx context.Context, client *storage.Client, pathStr string) ([]string, error) {
	if strings.HasPrefix(pathStr, "gs://") {
		trimmed := strings.TrimPrefix(pathStr, "gs://")
		bucketName, prefix, _ := strings.Cut(trimmed, "/")
		bucket := client.Bucket(bucketName)
		objs, err := gcs.ListBucketObjects(ctx, bucket, prefix)
		if err != nil {
			return nil, err
		}
		var fullPaths []string
		for _, obj := range objs {
			if strings.HasSuffix(obj, "/") || !strings.HasSuffix(obj, ".json") || strings.HasSuffix(obj, ".metrics.json") {
				continue
			}
			fullPaths = append(fullPaths, fmt.Sprintf("gs://%s/%s", bucketName, obj))
		}

		return fullPaths, nil
	}

	var files []string
	err := filepath.WalkDir(pathStr, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") && !strings.HasSuffix(p, ".metrics.json") {
			files = append(files, p)
		}

		return nil
	})

	return files, err
}

func readVulnerability(ctx context.Context, client *storage.Client, fullPath string) (*osvschema.Vulnerability, error) {
	if strings.HasPrefix(fullPath, "gs://") {
		trimmed := strings.TrimPrefix(fullPath, "gs://")
		bucketName, objName, _ := strings.Cut(trimmed, "/")
		rc, err := client.Bucket(bucketName).Object(objName).NewReader(ctx)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		file, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		var vuln osvschema.Vulnerability
		if err := protojson.Unmarshal(file, &vuln); err != nil {
			return nil, err
		}

		return &vuln, nil
	}

	file, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}
	var vuln osvschema.Vulnerability
	if err := protojson.Unmarshal(file, &vuln); err != nil {
		return nil, err
	}

	return &vuln, nil
}

func combineOneOSVRecord(cveID models.CVEID, cve5 *osvschema.Vulnerability, nvd *osvschema.Vulnerability, mandatoryCVEIDs []string) *osvschema.Vulnerability {
	var baseOSV *osvschema.Vulnerability
	if cve5 != nil && nvd != nil {
		baseOSV = combineTwoOSVRecords(cve5, nvd)
	} else if cve5 != nil {
		baseOSV = cve5
	} else if nvd != nil {
		baseOSV = nvd
	} else {
		return nil
	}

	if len(baseOSV.GetAffected()) == 0 || !hasRanges(baseOSV.GetAffected()) {
		if !slices.Contains(mandatoryCVEIDs, string(cveID)) {
			return nil
		}
	}

	return baseOSV
}

func readAndCombineWorker(ctx context.Context, client *storage.Client, workChan <-chan *CVEWorkItem, vulnChan chan<- *osvschema.Vulnerability, mandatoryCVEIDs []string) {
	for work := range workChan {
		var cve5, nvd *osvschema.Vulnerability
		var cve5Err, nvdErr error
		var readWg sync.WaitGroup

		if work.CVE5Path != "" {
			readWg.Add(1)
			go func() {
				defer readWg.Done()
				cve5, cve5Err = readVulnerability(ctx, client, work.CVE5Path)
				if cve5Err != nil {
					logger.Warn("Failed to read CVE5", slog.String("id", string(work.ID)), slog.Any("err", cve5Err))
				}
			}()
		}

		if work.NVDPath != "" {
			readWg.Add(1)
			go func() {
				defer readWg.Done()
				nvd, nvdErr = readVulnerability(ctx, client, work.NVDPath)
				if nvdErr != nil {
					logger.Warn("Failed to read NVD", slog.String("id", string(work.ID)), slog.Any("err", nvdErr))
				}
			}()
		}

		readWg.Wait()

		combined := combineOneOSVRecord(work.ID, cve5, nvd, mandatoryCVEIDs)
		if combined != nil {
			vulnChan <- combined
		}
	}
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	cve5Path := flag.String("cve5-path", defaultCVE5Path, "Path to CVE5 OSV files")
	nvdPath := flag.String("nvd-path", defaultNVDOSVPath, "Path to NVD OSV files")
	osvOutputPath := flag.String("osv-output-path", defaultOSVOutputPath, "Local output path of combined OSV files, or GCS prefix if uploading.")
	outputBucketName := flag.String("output-bucket", "osv-test-cve-osv-conversion", "The GCS bucket to write to.")
	overridesBucketName := flag.String("overrides-bucket", "osv-test-cve-osv-conversion", "The GCS bucket to read overrides from.")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "If true, upload to GCS bucket instead of writing to local disk.")
	numWorkers := flag.Int("workers", 64, "Number of workers to process records")
	syncDeletions := flag.Bool("sync-deletions", false, "If false, do not delete files in bucket that are not local")
	flag.Parse()

	err := os.MkdirAll(*osvOutputPath, 0755)
	if err != nil {
		logger.Fatal("Can't create output path", slog.Any("err", err))
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		logger.Fatal("Failed to create storage client", slog.Any("err", err))
	}
	defer client.Close()

	var debianCVEs, alpineCVEs []string
	var debianErr, alpineErr error

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		debianCVEs, debianErr = listBucketObjects(ctx, client, "osv-test-debian-osv", "/debian-cve-osv")
		if debianErr != nil {
			logger.Warn("Failed to list debian cves", slog.Any("err", debianErr))
		} else {
			for i, filename := range debianCVEs {
				cve := extractCVEName(filename, "DEBIAN-")
				if cve != "" {
					debianCVEs[i] = cve
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		alpineCVEs, alpineErr = listBucketObjects(ctx, client, "osv-test-cve-osv-conversion", "/alpine")
		if alpineErr != nil {
			logger.Warn("Failed to list alpine cves", slog.Any("err", alpineErr))
		} else {
			for i, filename := range alpineCVEs {
				cve := extractCVEName(filename, "ALPINE-")
				if cve != "" {
					alpineCVEs[i] = cve
				}
			}
		}
	}()

	wg.Wait()

	mandatoryCVEIDs := append(debianCVEs, alpineCVEs...) //nolint:gocritic

	// List CVE5 and NVD objects
	var cve5Files, nvdFiles []string
	var cve5ListErr, nvdListErr error
	var listWg sync.WaitGroup
	listWg.Add(2)

	go func() {
		defer listWg.Done()
		logger.Info("Listing CVE5 objects", slog.String("path", *cve5Path))
		cve5Files, cve5ListErr = listObjects(ctx, client, *cve5Path)
		if cve5ListErr != nil {
			logger.Fatal("Failed to list CVE5 objects", slog.Any("err", cve5ListErr))
		}
	}()

	go func() {
		defer listWg.Done()
		logger.Info("Listing NVD objects", slog.String("path", *nvdPath))
		nvdFiles, nvdListErr = listObjects(ctx, client, *nvdPath)
		if nvdListErr != nil {
			logger.Fatal("Failed to list NVD objects", slog.Any("err", nvdListErr))
		}
	}()

	listWg.Wait()

	// Build work items
	workItems := make(map[models.CVEID]*CVEWorkItem)
	for _, f := range cve5Files {
		id := cveIDFromPath(f)
		if id != "" {
			if _, ok := workItems[id]; !ok {
				workItems[id] = &CVEWorkItem{ID: id}
			}
			workItems[id].CVE5Path = f
		}
	}

	for _, f := range nvdFiles {
		id := cveIDFromPath(f)
		if id != "" {
			if _, ok := workItems[id]; !ok {
				workItems[id] = &CVEWorkItem{ID: id}
			}
			workItems[id].NVDPath = f
		}
	}

	logger.Info("Total CVE Work Items to process", slog.Int("count", len(workItems)))

	// Start Upload Pool
	var outBkt, overridesBkt *storage.BucketHandle
	var gcsHelper *gcs.Helper
	if *uploadToGCS {
		outBkt = client.Bucket(*outputBucketName)
		if *overridesBucketName != "" {
			overridesBkt = client.Bucket(*overridesBucketName)
		}
		gcsHelper, err = gcs.InitUploadPool(ctx, *numWorkers, *outputBucketName)
		if err != nil {
			logger.Fatal("Failed to initialize GCS upload pool", slog.Any("err", err))
		}
		defer gcsHelper.CloseAndWait()
	}

	// Start Channels
	vulnChan := make(chan *osvschema.Vulnerability, *numWorkers)
	validVulnChan := make(chan *osvschema.Vulnerability, *numWorkers)
	workChan := make(chan *CVEWorkItem, *numWorkers)

	// Start VulnWorkers (Upload side)
	var uploadWg sync.WaitGroup
	var successCount atomic.Uint64
	for range *numWorkers {
		uploadWg.Add(1)
		go func() {
			defer uploadWg.Done()
			writer.VulnWorker(ctx, validVulnChan, outBkt, overridesBkt, gcsHelper, *osvOutputPath, &successCount)
		}()
	}

	// Interpose Collector to gather valid IDs
	var validIDs []string
	var idWg sync.WaitGroup
	idWg.Add(1)
	totalWork := len(workItems)
	go func() {
		defer idWg.Done()
		count := 0
		for v := range vulnChan {
			count++
			if len(v.GetAffected()) > 0 {
				validIDs = append(validIDs, v.GetId())
			}
			validVulnChan <- v
			if count%1000 == 0 {
				logger.Info("Processed CVEs", slog.Int("count", count), slog.Int("total", totalWork), slog.Int("percent", (count*100)/totalWork))
			}
		}
		close(validVulnChan)
	}()

	// Start ReadAndCombineWorkers (Read side)
	var readWg sync.WaitGroup
	for range *numWorkers {
		readWg.Add(1)
		go func() {
			defer readWg.Done()
			readAndCombineWorker(ctx, client, workChan, vulnChan, mandatoryCVEIDs)
		}()
	}

	// Feed Work
	go func() {
		for _, work := range workItems {
			workChan <- work
		}
		close(workChan)
	}()

	// Wait for reads to finish
	readWg.Wait()
	close(vulnChan)

	// Wait for collector and uploads to finish
	idWg.Wait()
	uploadWg.Wait()

	logger.Info("Successfully processed OSV files", slog.Int("count", len(validIDs)))
	if outBkt == nil && gcsHelper == nil {
		logger.Info("Successfully wrote records to disk", slog.Uint64("count", successCount.Load()))
	}

	// Handle Deletion
	if *syncDeletions && *uploadToGCS {
		writer.HandleDeletion(ctx, outBkt, *osvOutputPath, validIDs)
	}
}

// extractCVEName extracts the CVE name from a given filename and prefix.
// It returns an empty string if the filename does not start with "CVE".
func extractCVEName(filename string, prefix string) string {
	cleaned := strings.TrimPrefix(filename, prefix)
	cleaned = strings.TrimSuffix(cleaned, ".json")
	pre := strings.Split(cleaned, "-")
	if pre[0] != "CVE" {
		return ""
	}

	return cleaned
}

// listBucketObjects lists the names of all objects in a Google Cloud Storage bucket.
// It does not download the file contents.
func listBucketObjects(ctx context.Context, client *storage.Client, bucketName string, prefix string) ([]string, error) {
	bucket := client.Bucket(bucketName)
	it := bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	var filenames []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break // All objects have been listed.
		}
		if err != nil {
			return nil, fmt.Errorf("bucket.Objects: %w", err)
		}
		filenames = append(filenames, attrs.Name)
	}

	return filenames, nil
}

// combineTwoOSVRecords takes two osv records and combines them into one
func combineTwoOSVRecords(cve5 *osvschema.Vulnerability, nvd *osvschema.Vulnerability) *osvschema.Vulnerability {
	baseOSV := cve5
	combinedAffected := pickAffectedInformation(cve5.GetAffected(), nvd.GetAffected())

	baseOSV.Affected = combinedAffected
	// Merge references, ensuring no duplicates.
	refMap := make(map[string]bool)
	for _, r := range baseOSV.GetReferences() {
		refMap[r.GetUrl()] = true
	}
	for _, r := range nvd.GetReferences() {
		if !refMap[r.GetUrl()] {
			baseOSV.References = append(baseOSV.References, r)
			refMap[r.GetUrl()] = true
		}
	}

	slices.SortFunc(baseOSV.GetReferences(), func(a, b *osvschema.Reference) int {
		return cmp.Or(
			cmp.Compare(a.GetType(), b.GetType()),
			cmp.Compare(a.GetUrl(), b.GetUrl()),
		)
	})

	// Merge timestamps: latest modified, earliest published.
	cve5Modified := baseOSV.GetModified()
	if nvd.GetModified().AsTime().After(cve5Modified.AsTime()) {
		baseOSV.Modified = nvd.GetModified()
	}

	cve5Published := baseOSV.GetPublished()
	if nvd.GetPublished().AsTime().Before(cve5Published.AsTime()) {
		baseOSV.Published = nvd.GetPublished()
	}

	// Merge aliases, ensuring no duplicates.
	aliasMap := make(map[string]bool)
	for _, alias := range baseOSV.GetAliases() {
		aliasMap[alias] = true
	}
	for _, alias := range nvd.GetAliases() {
		if !aliasMap[alias] {
			baseOSV.Aliases = append(baseOSV.Aliases, alias)
			aliasMap[alias] = true
		}
	}

	return baseOSV
}

// pickAffectedInformation merges information from nvdAffected into cve5Affected.
// It matches affected packages by the repo URL in their version ranges.
// If a match is found, it merges the version range information, preferring the entry
// with more ranges. Unmatched nvdAffected packages are appended.
// It returns a new slice and does not modify cve5Affected in place.
func pickAffectedInformation(cve5Affected []*osvschema.Affected, nvdAffected []*osvschema.Affected) []*osvschema.Affected {
	if len(nvdAffected) == 0 {
		for _, aff := range cve5Affected {
			for _, r := range aff.GetRanges() {
				cleanLastAffectedIfFixedExists(r)
			}
		}

		return cve5Affected
	}

	if len(cve5Affected) == 0 {
		for _, aff := range nvdAffected {
			for _, r := range aff.GetRanges() {
				cleanLastAffectedIfFixedExists(r)
			}
		}

		return nvdAffected
	}

	// Group all ranges by repository URL
	cve5Ranges := make(map[string]*osvschema.Range)
	for _, aff := range cve5Affected {
		for _, r := range aff.GetRanges() {
			if r.GetRepo() != "" {
				repo := strings.ToLower(r.GetRepo())
				if _, exists := cve5Ranges[repo]; exists {
					logger.Error("Duplicate range found for repository in CVE5 affected ranges", slog.String("repo", repo))
				}
				cve5Ranges[repo] = r
			}
		}
	}

	nvdRanges := make(map[string]*osvschema.Range)
	for _, aff := range nvdAffected {
		for _, r := range aff.GetRanges() {
			if r.GetRepo() != "" {
				repo := strings.ToLower(r.GetRepo())
				if _, exists := nvdRanges[repo]; exists {
					logger.Error("Duplicate range found for repository in NVD affected ranges", slog.String("repo", repo))
				}
				nvdRanges[repo] = r
			}
		}
	}

	// Collect all unique repo URLs
	reposMap := make(map[string]bool)
	for repo := range cve5Ranges {
		reposMap[repo] = true
	}
	for repo := range nvdRanges {
		reposMap[repo] = true
	}

	var finalRanges []*osvschema.Range
	for repo := range reposMap {
		bestRange := pickBestRange(cve5Ranges[repo], nvdRanges[repo])
		if bestRange != nil {
			finalRanges = append(finalRanges, bestRange)
		}
	}

	// Separate output Affected list:
	// 1. Those that have ranges are grouped under a single Affected struct.
	// 2. Those that do not have ranges are kept as separate Affected structs.
	var combinedAffected []*osvschema.Affected

	if len(finalRanges) > 0 {
		// Sort final ranges by repo for stability
		slices.SortFunc(finalRanges, func(a, b *osvschema.Range) int {
			return cmp.Compare(strings.ToLower(a.GetRepo()), strings.ToLower(b.GetRepo()))
		})

		// Find Package and EcosystemSpecific if any were present in the input ranges, and collect versions.
		var pkg *osvschema.Package
		var ecosystemSpecific *structpb.Struct
		var versions []string
		for _, aff := range cve5Affected {
			if len(aff.GetRanges()) > 0 {
				versions = append(versions, aff.GetVersions()...)
				if aff.GetPackage() != nil {
					pkg = aff.GetPackage()
				}
				if aff.GetEcosystemSpecific() != nil {
					ecosystemSpecific = aff.GetEcosystemSpecific()
				}
			}
		}
		for _, aff := range nvdAffected {
			if len(aff.GetRanges()) > 0 {
				versions = append(versions, aff.GetVersions()...)
				if pkg == nil && aff.GetPackage() != nil {
					pkg = aff.GetPackage()
				}
				if ecosystemSpecific == nil && aff.GetEcosystemSpecific() != nil {
					ecosystemSpecific = aff.GetEcosystemSpecific()
				}
			}
		}

		if len(versions) > 0 {
			slices.Sort(versions)
			versions = slices.Compact(versions)
		} else {
			versions = nil
		}

		combinedAffected = append(combinedAffected, &osvschema.Affected{
			Ranges:            finalRanges,
			Package:           pkg,
			EcosystemSpecific: ecosystemSpecific,
			Versions:          versions,
		})
	}

	// Copy over affected objects from cve5 and nvd that have NO ranges (e.g. pure package entries),
	// deduplicating them by package name.
	seenPackages := make(map[string]bool)
	for _, aff := range cve5Affected {
		if len(aff.GetRanges()) == 0 && aff.GetPackage() != nil {
			pkgName := strings.ToLower(aff.GetPackage().GetName())
			if !seenPackages[pkgName] {
				combinedAffected = append(combinedAffected, aff)
				seenPackages[pkgName] = true
			}
		}
	}
	for _, aff := range nvdAffected {
		if len(aff.GetRanges()) == 0 && aff.GetPackage() != nil {
			pkgName := strings.ToLower(aff.GetPackage().GetName())
			if !seenPackages[pkgName] {
				combinedAffected = append(combinedAffected, aff)
				seenPackages[pkgName] = true
			}
		}
	}

	// Sort the combinedAffected array: first entries with ranges, then by package name if present.
	slices.SortFunc(combinedAffected, func(a, b *osvschema.Affected) int {
		hasRangeA := len(a.GetRanges()) > 0
		hasRangeB := len(b.GetRanges()) > 0
		if hasRangeA != hasRangeB {
			if hasRangeA {
				return -1
			}

			return 1
		}
		var pkgA, pkgB string
		if a.GetPackage() != nil {
			pkgA = a.GetPackage().GetName()
		}
		if b.GetPackage() != nil {
			pkgB = b.GetPackage().GetName()
		}

		return cmp.Compare(strings.ToLower(pkgA), strings.ToLower(pkgB))
	})

	return combinedAffected
}

type ExtractedEvent struct {
	Introduced   string
	Fixed        string
	LastAffected string
	Limit        string
}

func getExtractedEvents(r *osvschema.Range) []*structpb.Value {
	if r.GetDatabaseSpecific() == nil {
		return nil
	}
	fields := r.GetDatabaseSpecific().GetFields()
	if fields == nil {
		return nil
	}
	val, ok := fields["extracted_events"]
	if !ok || val.GetListValue() == nil {
		return nil
	}

	return val.GetListValue().GetValues()
}

func parseExtractedEvent(v *structpb.Value) ExtractedEvent {
	s := v.GetStructValue()
	if s == nil {
		return ExtractedEvent{}
	}
	fields := s.GetFields()
	var ev ExtractedEvent
	if intro, ok := fields["introduced"]; ok {
		ev.Introduced = intro.GetStringValue()
	}
	if fixed, ok := fields["fixed"]; ok {
		ev.Fixed = fixed.GetStringValue()
	}
	if la, ok := fields["last_affected"]; ok {
		ev.LastAffected = la.GetStringValue()
	}
	if lim, ok := fields["limit"]; ok {
		ev.Limit = lim.GetStringValue()
	}

	return ev
}

func parseExtractedEvents(r *osvschema.Range) []ExtractedEvent {
	rawValues := getExtractedEvents(r)
	if len(rawValues) == 0 {
		return nil
	}
	events := make([]ExtractedEvent, 0, len(rawValues))
	for _, val := range rawValues {
		events = append(events, parseExtractedEvent(val))
	}

	return events
}

// sameVersionRanges checks if two ranges have the same extracted events.
func sameVersionRanges(evs1, evs2 []ExtractedEvent) bool {
	if len(evs1) != len(evs2) {
		return false
	}
	for i := range evs1 {
		if evs1[i] != evs2[i] {
			return false
		}
	}

	return true
}

// hasFixedEvent checks if any event in the range has a fixed field.
func hasFixedEvent(r *osvschema.Range) bool {
	for _, e := range r.GetEvents() {
		if e.GetFixed() != "" {
			return true
		}
	}

	return false
}

// hasIntroducedZero checks if any event in the range has an introduced field with "0".
func hasIntroducedZero(r *osvschema.Range) bool {
	for _, e := range r.GetEvents() {
		if e.GetIntroduced() == "0" {
			return true
		}
	}

	return false
}

// isCPERange checks if the range is a CPE range.
func isCPERange(r *osvschema.Range) bool {
	if r.GetDatabaseSpecific() == nil {
		return false
	}
	fields := r.GetDatabaseSpecific().GetFields()
	if fields == nil {
		return false
	}
	val, ok := fields["source"]
	if !ok {
		return false
	}
	if val.GetStringValue() == "CPE_RANGE" {
		return true
	}
	if listVal := val.GetListValue(); listVal != nil {
		for _, item := range listVal.GetValues() {
			if item.GetStringValue() == "CPE_RANGE" {
				return true
			}
		}
	}

	return false
}

// cleanLastAffectedIfFixedExists removes the last_affected field from all
// events in the range if any event has a fixed field. This happens in place.
func cleanLastAffectedIfFixedExists(r *osvschema.Range) {
	if r == nil {
		return
	}
	hasFixed := false
	for _, e := range r.GetEvents() {
		if e.GetFixed() != "" {
			hasFixed = true
			break
		}
	}
	if !hasFixed {
		return
	}
	var cleanEvents []*osvschema.Event
	for _, e := range r.GetEvents() {
		if e.GetLastAffected() == "" {
			cleanEvents = append(cleanEvents, e)
		}
	}
	r.Events = cleanEvents
}

// isReferencesOnly checks if the range 'source' field is only "REFERENCES"
// or ["REFERENCES"].
func isReferencesOnly(r *osvschema.Range) bool {
	if r.GetDatabaseSpecific() == nil {
		return false
	}
	fields := r.GetDatabaseSpecific().GetFields()
	if fields == nil {
		return false
	}
	val, ok := fields["source"]
	if !ok {
		return false
	}
	if val.GetStringValue() == "REFERENCES" {
		return true
	}
	if listVal := val.GetListValue(); listVal != nil {
		values := listVal.GetValues()
		if len(values) == 1 && values[0].GetStringValue() == "REFERENCES" {
			return true
		}
	}

	return false
}

func mergeDatabaseSpecifics(ds1, ds2 *structpb.Struct) *structpb.Struct {
	if ds1 == nil {
		return ds2
	}
	if ds2 == nil {
		return ds1
	}

	mergedMap := make(map[string]any)
	for k, v := range ds1.GetFields() {
		mergedMap[k] = v.AsInterface()
	}

	for k, v := range ds2.GetFields() {
		val2 := v.AsInterface()
		if existing, ok := mergedMap[k]; ok {
			mergedVal, err := conversion.MergeDatabaseSpecificValues(existing, val2)
			if err == nil {
				mergedMap[k] = mergedVal
			}
		} else {
			mergedMap[k] = val2
		}
	}

	if ds, err := utility.NewStructpbFromMap(mergedMap); err == nil {
		return ds
	}

	return ds1
}

// mergeRanges merges two version ranges into one.
// This function enforces the following invariants (and will return an error if they are violated):
//  1. The two ranges must share the same Type and Repository URL.
//  2. At least one of the two ranges must be references-only (meaning its database-specific
//     source metadata is strictly "REFERENCES" or ["REFERENCES"]). This guarantees that the
//     operation is limited to appending standalone commit events from advisory links, avoiding
//     the corruption of paired version boundaries in complex ranges.
func mergeRanges(base, other *osvschema.Range) (*osvschema.Range, error) {
	if base.GetType() != other.GetType() || !conversion.IsSameRepo(base.GetRepo(), other.GetRepo()) {
		return nil, fmt.Errorf("cannot merge ranges with mismatching Type/Repo: (%s, %s) and (%s, %s)",
			base.GetType(), base.GetRepo(), other.GetType(), other.GetRepo())
	}

	isBaseRefsOnly := isReferencesOnly(base)
	isOtherRefsOnly := isReferencesOnly(other)

	if !isBaseRefsOnly && !isOtherRefsOnly {
		return nil, fmt.Errorf("invariance violation: mergeRanges can only be called when at least one range is references-only. Base: %v, Other: %v",
			base.GetDatabaseSpecific(), other.GetDatabaseSpecific())
	}

	hasNonZeroIntroduced := false
	for _, e := range base.GetEvents() {
		if e.GetIntroduced() != "" && e.GetIntroduced() != "0" {
			hasNonZeroIntroduced = true
			break
		}
	}
	if !hasNonZeroIntroduced {
		for _, e := range other.GetEvents() {
			if e.GetIntroduced() != "" && e.GetIntroduced() != "0" {
				hasNonZeroIntroduced = true
				break
			}
		}
	}

	var baseFixed []*osvschema.Event
	for _, e := range base.GetEvents() {
		if e.GetFixed() != "" {
			baseFixed = append(baseFixed, e)
		}
	}

	var otherFixed []*osvschema.Event
	for _, e := range other.GetEvents() {
		if e.GetFixed() != "" {
			otherFixed = append(otherFixed, e)
		}
	}

	baseEvents := make([]*osvschema.Event, 0, len(base.GetEvents()))
	replaceFixed := len(baseFixed) == 1 && len(otherFixed) >= 1
	for _, e := range base.GetEvents() {
		if replaceFixed && e.GetFixed() != "" {
			continue
		}
		if hasNonZeroIntroduced && isBaseRefsOnly && e.GetIntroduced() == "0" {
			continue
		}
		baseEvents = append(baseEvents, e)
	}

	merged := &osvschema.Range{
		Type:             base.GetType(),
		Repo:             base.GetRepo(),
		Events:           baseEvents,
		DatabaseSpecific: mergeDatabaseSpecifics(base.GetDatabaseSpecific(), other.GetDatabaseSpecific()),
	}
	for _, e := range other.GetEvents() {
		if hasNonZeroIntroduced && isOtherRefsOnly && e.GetIntroduced() == "0" {
			continue
		}
		found := false
		for _, existing := range merged.GetEvents() {
			if e.GetIntroduced() != "" && e.GetIntroduced() == existing.GetIntroduced() {
				found = true
				break
			}
			if e.GetFixed() != "" && e.GetFixed() == existing.GetFixed() {
				found = true
				break
			}
			if e.GetLastAffected() != "" && e.GetLastAffected() == existing.GetLastAffected() {
				found = true
				break
			}
		}
		if !found {
			if e.GetIntroduced() != "" {
				merged.Events = append([]*osvschema.Event{e}, merged.GetEvents()...)
			} else {
				merged.Events = append(merged.Events, e)
			}
		}
	}
	slices.SortStableFunc(merged.GetEvents(), func(a, b *osvschema.Event) int {
		if a.GetIntroduced() != "" && b.GetIntroduced() == "" {
			return -1
		}
		if a.GetIntroduced() == "" && b.GetIntroduced() != "" {
			return 1
		}

		return 0
	})

	return merged, nil
}

// pickBestRange picks the best range between two ranges.
// It prefers cve5Range over nvdRange if both ranges have fixed information.
// If one range is references-only, it merges them instead of choosing one.
// More information can be found in the DESIGN.md file in this folder
func pickBestRange(cve5Range *osvschema.Range, nvdRange *osvschema.Range) *osvschema.Range {
	if cve5Range == nil {
		cleanLastAffectedIfFixedExists(nvdRange)
		return nvdRange
	}
	if nvdRange == nil {
		cleanLastAffectedIfFixedExists(cve5Range)
		return cve5Range
	}

	// If one of the ranges is references-only, merge them instead of choosing one
	if isReferencesOnly(nvdRange) {
		merged, err := mergeRanges(cve5Range, nvdRange)
		if err != nil {
			logger.Error("Failed to merge references-only range, falling back to CVE5 range", slog.Any("err", err))
			return cve5Range
		}
		cleanLastAffectedIfFixedExists(merged)

		return merged
	}
	if isReferencesOnly(cve5Range) {
		merged, err := mergeRanges(nvdRange, cve5Range)
		if err != nil {
			logger.Error("Failed to merge references-only range, falling back to NVD range", slog.Any("err", err))
			return nvdRange
		}
		cleanLastAffectedIfFixedExists(merged)

		return merged
	}

	//  Try to merge boundary versions first for simple 1-event/2-event ranges.
	var merged *osvschema.Range
	if len(cve5Range.GetEvents()) <= 2 && len(nvdRange.GetEvents()) <= 2 {
		c5Intro, c5LastAffected, c5Fixed := getRangeBoundaryVersions(cve5Range.GetEvents())
		nvdIntro, nvdLastAffected, nvdFixed := getRangeBoundaryVersions(nvdRange.GetEvents())

		// Prefer cve5 bounds, but use nvd if cve5 is missing them
		if c5Intro == "" {
			c5Intro = nvdIntro
		}
		if c5LastAffected == "" {
			c5LastAffected = nvdLastAffected
		}
		if c5Fixed == "" {
			c5Fixed = nvdFixed
		}

		if c5Intro != "" || c5LastAffected != "" || c5Fixed != "" {
			merged = conversion.BuildGitVersionRange(c5Intro, c5LastAffected, c5Fixed, cve5Range.GetRepo())
			merged.DatabaseSpecific = mergeDatabaseSpecifics(cve5Range.GetDatabaseSpecific(), nvdRange.GetDatabaseSpecific())
		}
	}

	if merged == nil {
		// Prioritize range with fixed information over last_affected / open-ended ranges
		c5HasFixed := hasFixedEvent(cve5Range)
		nvdHasFixed := hasFixedEvent(nvdRange)

		if c5HasFixed != nvdHasFixed {
			if c5HasFixed {
				merged = cve5Range
			} else {
				merged = nvdRange
			}
		}
	}

	if merged == nil {
		// Prefer constrained ranges (no introduced "0")
		c5HasIntroZero := hasIntroducedZero(cve5Range)
		nvdHasIntroZero := hasIntroducedZero(nvdRange)

		if c5HasIntroZero != nvdHasIntroZero {
			if !c5HasIntroZero {
				merged = cve5Range
			} else {
				merged = nvdRange
			}
		}
	}

	if merged == nil {
		// Prefer CPE_RANGE if it exists, otherwise fall back to preferred source (CVE5)
		c5IsCPERange := isCPERange(cve5Range)
		nvdIsCPERange := isCPERange(nvdRange)

		if c5IsCPERange != nvdIsCPERange {
			if c5IsCPERange {
				merged = cve5Range
			} else {
				merged = nvdRange
			}
		}
	}

	if merged == nil {
		cve5Evs := parseExtractedEvents(cve5Range)
		nvdEvs := parseExtractedEvents(nvdRange)

		if !sameVersionRanges(cve5Evs, nvdEvs) && len(cve5Evs) > 0 && len(nvdEvs) > 0 {
			// Different version ranges defined, prioritize preferred source (CVE5)
			merged = cve5Range
		}
	}

	if merged == nil {
		// Fallback: choose the one with more complete Git commits (more events)
		if len(nvdRange.GetEvents()) > len(cve5Range.GetEvents()) {
			merged = nvdRange
		} else {
			merged = cve5Range
		}
	}

	// Remove last_affected events if a fixed commit exists
	cleanLastAffectedIfFixedExists(merged)

	return merged
}

func hasRanges(affected []*osvschema.Affected) bool {
	for _, a := range affected {
		if len(a.GetRanges()) > 0 {
			return true
		}
	}

	return false
}

// getRangeBoundaryVersions extracts the introduced, last_affected and fixed versions from a slice of OSV events.
// It iterates through the events and returns the last non-empty "introduced", "last_affected" and "fixed" versions found.
func getRangeBoundaryVersions(events []*osvschema.Event) (introduced, lastAffected, fixed string) {
	for _, e := range events {
		if e.GetIntroduced() != "0" && e.GetIntroduced() != "" {
			introduced = e.GetIntroduced()
		}
		if e.GetLastAffected() != "" {
			lastAffected = e.GetLastAffected()
		}
		if e.GetFixed() != "" {
			fixed = e.GetFixed()
		}
	}

	return introduced, lastAffected, fixed
}
