// package main combines CVEs and security advisories into OSV records.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/conversion/writer"
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

	// Load CVE5 OSVs
	allCVE5 := loadOSV(*cve5Path)
	// Load NVD OSVs
	allNVD := loadOSV(*nvdPath)
	debianCVEs, err := listBucketObjects("osv-test-debian-osv", "/debian-cve-osv")
	if err != nil {
		logger.Warn("Failed to list debian cves", slog.Any("err", err))
	} else {
		for i, filename := range debianCVEs {
			cve := extractCVEName(filename, "DEBIAN-")
			if cve != "" {
				debianCVEs[i] = cve
			}
		}
	}

	// run extract file name on each element in debianCVEs and alpineCVEs.
	alpineCVEs, err := listBucketObjects("osv-test-cve-osv-conversion", "/alpine")
	if err != nil {
		logger.Warn("Failed to list alpine cves", slog.Any("err", err))
	} else {
		for i, filename := range alpineCVEs {
			cve := extractCVEName(filename, "ALPINE-")
			if cve != "" {
				alpineCVEs[i] = cve
			}
		}
	}

	// this ensures the creation of CVEs even if they don't have packages
	// to ensure Alpine and Debian CVEs have an upstream CVE.
	// linter is compaining that we aren't appending to the same slice, but we
	// just want to combine these two arrays with a more descriptive name.
	mandatoryCVEIDs := append(debianCVEs, alpineCVEs...) //nolint:gocritic
	combinedData := combineIntoOSV(allCVE5, allNVD, mandatoryCVEIDs)

	ctx := context.Background()

	vulnerabilities := make([]*osvschema.Vulnerability, 0, len(combinedData))
	for _, v := range combinedData {
		vulnerabilities = append(vulnerabilities, v)
	}

	writer.UploadVulnsToGCS(ctx, "OSV files", *uploadToGCS, *outputBucketName, *overridesBucketName, *numWorkers, *osvOutputPath, vulnerabilities, *syncDeletions)
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
func listBucketObjects(bucketName string, prefix string) ([]string, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}
	defer client.Close()
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

// loadOSV recursively loads all OSV vulnerabilities from a given directory path.
// It walks the directory, reads each ".json" file, and decodes it into an osvschema.Vulnerability object.
// The function returns a map of CVE IDs to their corresponding Vulnerability objects.
// Files that are not ".json" files, directories, or files ending in ".metrics.json" are skipped.
// The function will log warnings for files that fail to open or decode, and will terminate if it fails to walk the directory.
func loadOSV(osvPath string) map[models.CVEID]*osvschema.Vulnerability {
	allVulns := make(map[models.CVEID]*osvschema.Vulnerability)
	logger.Info("Loading OSV records", slog.String("path", osvPath))
	err := filepath.WalkDir(osvPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".metrics.json") {
			return nil
		}

		file, err := os.ReadFile(path)
		if err != nil {
			logger.Warn("Failed to open OSV JSON file", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		var vuln osvschema.Vulnerability
		decodeErr := protojson.Unmarshal(file, &vuln)
		if decodeErr != nil {
			logger.Error("Failed to decode, skipping", slog.String("file", path), slog.Any("err", decodeErr))
			return nil
		}
		allVulns[models.CVEID(vuln.GetId())] = &vuln

		return nil
	})

	if err != nil {
		logger.Fatal("Failed to walk OSV directory", slog.String("path", osvPath), slog.Any("err", err))
	}

	return allVulns
}

// combineIntoOSV creates OSV entry by combining loaded CVEs from NVD and PackageInfo information from security advisories.
func combineIntoOSV(cve5osv map[models.CVEID]*osvschema.Vulnerability, nvdosv map[models.CVEID]*osvschema.Vulnerability, mandatoryCVEIDs []string) map[models.CVEID]*osvschema.Vulnerability {
	osvRecords := make(map[models.CVEID]*osvschema.Vulnerability)

	// Iterate through CVEs from security advisories (cve5) as the base
	for cveID, cve5 := range cve5osv {
		var baseOSV *osvschema.Vulnerability
		nvd, ok := nvdosv[cveID]

		if ok {
			baseOSV = combineTwoOSVRecords(cve5, nvd)
			// The CVE is processed, so remove it from the nvdosv map to avoid re-processing.
			delete(nvdosv, cveID)
		} else {
			baseOSV = cve5
		}

		if len(baseOSV.GetAffected()) == 0 || !hasRanges(baseOSV.GetAffected()) {
			// check if part exists.
			if !slices.Contains(mandatoryCVEIDs, string(cveID)) {
				continue
			}
		}
		osvRecords[cveID] = baseOSV
	}

	// Add any remaining CVEs from NVD that were not in the advisory data.
	for cveID, nvd := range nvdosv {
		if len(nvd.GetAffected()) == 0 || !hasRanges(nvd.GetAffected()) {
			continue
		}
		osvRecords[cveID] = nvd
	}

	return osvRecords
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

		// Find Package and EcosystemSpecific if any were present in the input ranges
		var pkg *osvschema.Package
		var ecosystemSpecific *structpb.Struct
		for _, aff := range cve5Affected {
			if len(aff.GetRanges()) > 0 {
				if aff.GetPackage() != nil {
					pkg = aff.GetPackage()
				}
				if aff.GetEcosystemSpecific() != nil {
					ecosystemSpecific = aff.GetEcosystemSpecific()
				}
			}
		}
		if pkg == nil || ecosystemSpecific == nil {
			for _, aff := range nvdAffected {
				if len(aff.GetRanges()) > 0 {
					if pkg == nil && aff.GetPackage() != nil {
						pkg = aff.GetPackage()
					}
					if ecosystemSpecific == nil && aff.GetEcosystemSpecific() != nil {
						ecosystemSpecific = aff.GetEcosystemSpecific()
					}
				}
			}
		}

		combinedAffected = append(combinedAffected, &osvschema.Affected{
			Ranges:            finalRanges,
			Package:           pkg,
			EcosystemSpecific: ecosystemSpecific,
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

	if !isReferencesOnly(base) && !isReferencesOnly(other) {
		return nil, fmt.Errorf("invariance violation: mergeRanges can only be called when at least one range is references-only. Base: %v, Other: %v",
			base.GetDatabaseSpecific(), other.GetDatabaseSpecific())
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
		baseEvents = append(baseEvents, e)
	}

	merged := &osvschema.Range{
		Type:             base.GetType(),
		Repo:             base.GetRepo(),
		Events:           baseEvents,
		DatabaseSpecific: mergeDatabaseSpecifics(base.GetDatabaseSpecific(), other.GetDatabaseSpecific()),
	}
	for _, e := range other.GetEvents() {
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
		c5Intro, c5Fixed := getRangeBoundaryVersions(cve5Range.GetEvents())
		nvdIntro, nvdFixed := getRangeBoundaryVersions(nvdRange.GetEvents())

		// Prefer cve5 bounds, but use nvd if cve5 is missing them
		if c5Intro == "" {
			c5Intro = nvdIntro
		}
		if c5Fixed == "" {
			c5Fixed = nvdFixed
		}

		if c5Intro != "" || c5Fixed != "" {
			merged = conversion.BuildGitVersionRange(c5Intro, "", c5Fixed, cve5Range.GetRepo())
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

// getRangeBoundaryVersions extracts the introduced and fixed versions from a slice of OSV events.
// It iterates through the events and returns the last non-empty "introduced" and "fixed" versions found.
func getRangeBoundaryVersions(events []*osvschema.Event) (introduced, fixed string) {
	for _, e := range events {
		if e.GetIntroduced() != "0" && e.GetIntroduced() != "" {
			introduced = e.GetIntroduced()
		}
		if e.GetFixed() != "" {
			fixed = e.GetFixed()
		}
	}

	return introduced, fixed
}
