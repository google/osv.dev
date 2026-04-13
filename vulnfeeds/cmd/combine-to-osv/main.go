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
	gitpurl "github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/upload"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	packageurl "github.com/package-url/packageurl-go"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protojson"
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

	upload.Upload(ctx, "OSV files", *uploadToGCS, *outputBucketName, *overridesBucketName, *numWorkers, *osvOutputPath, vulnerabilities, *syncDeletions)
}

// extractCVEName extracts the CVE name from a given filename and prefix.
// It returns an empty string if the filename does not start with "CVE".
func extractCVEName(filename string, prefix string) string {
	cleaned := strings.TrimPrefix(filename, prefix)
	cleaned = strings.TrimSuffix(cleaned, ".json")
	pre := strings.SplitAfter(cleaned, "-")
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
		filenames = append(filenames, attrs.Name, prefix)
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
		enrichRepoPURLs(baseOSV)
		osvRecords[cveID] = baseOSV
	}

	// Add any remaining CVEs from NVD that were not in the advisory data.
	for cveID, nvd := range nvdosv {
		if len(nvd.GetAffected()) == 0 || !hasRanges(nvd.GetAffected()) {
			continue
		}
		enrichRepoPURLs(nvd)
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
		return cve5Affected
	}
	if len(cve5Affected) == 0 || len(nvdAffected) > len(cve5Affected) {
		return nvdAffected
	}

	cve5Ranges, cve5Versions := bucketByRepo(cve5Affected)
	nvdRanges, nvdVersions := bucketByRepo(nvdAffected)

	newRepoAffectedMap := make(map[string]*osvschema.Affected)

	// Finds ranges with the same repo and merges them into one affected set.
	for repo, cveRanges := range cve5Ranges {
		if nvd, ok := nvdRanges[repo]; ok {
			var newAffectedRanges []*osvschema.Range

			// Found a match. If NVD has more ranges, use its ranges.
			if len(nvd) > len(cveRanges) {
				newAffectedRanges = nvd
			} else if len(cveRanges) == 1 && len(nvd) == 1 {
				c5Intro, c5Fixed := getRangeBoundaryVersions(cveRanges[0].GetEvents())
				nvdIntro, nvdFixed := getRangeBoundaryVersions(nvd[0].GetEvents())

				// Prefer cve5 data, but use nvd data if cve5 data is missing.
				if c5Intro == "" {
					c5Intro = nvdIntro
				}
				if c5Fixed == "" {
					c5Fixed = nvdFixed
				}

				if c5Intro != "" || c5Fixed != "" {
					newRange := conversion.BuildGitVersionRange(c5Intro, "", c5Fixed, repo)
					newAffectedRanges = append(newAffectedRanges, newRange)
				} else {
					newAffectedRanges = cveRanges
				}
			} else {
				newAffectedRanges = cveRanges
			}

			delete(nvdRanges, repo)
			newRepoAffectedMap[repo] = &osvschema.Affected{
				Ranges:   newAffectedRanges,
				Versions: vulns.Unique(slices.Concat(cve5Versions[repo], nvdVersions[repo])),
			}
		} else {
			newRepoAffectedMap[repo] = &osvschema.Affected{
				Ranges:   cveRanges,
				Versions: vulns.Unique(cve5Versions[repo]),
			}
		}
	}

	// Add remaining NVD packages that were not in cve5.
	for repo, nvdRange := range nvdRanges {
		newRepoAffectedMap[repo] = &osvschema.Affected{
			Ranges:   nvdRange,
			Versions: vulns.Unique(nvdVersions[repo]),
		}
	}

	combinedAffected := make([]*osvschema.Affected, 0, len(newRepoAffectedMap))
	for _, aff := range newRepoAffectedMap {
		combinedAffected = append(combinedAffected, aff)
	}

	// sort by repo
	slices.SortFunc(combinedAffected, func(a, b *osvschema.Affected) int {
		var repoA, repoB string
		if len(a.GetRanges()) > 0 {
			repoA = a.GetRanges()[0].GetRepo()
		}
		if len(b.GetRanges()) > 0 {
			repoB = b.GetRanges()[0].GetRepo()
		}

		return cmp.Compare(repoA, repoB)
	})

	return combinedAffected
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

// bucketByRepo groups each Affected's ranges (and the parent Affected's
// Versions) by the lowercased repo URL of every GIT-bearing range.
func bucketByRepo(affected []*osvschema.Affected) (map[string][]*osvschema.Range, map[string][]string) {
	ranges := make(map[string][]*osvschema.Range)
	versions := make(map[string][]string)
	for _, a := range affected {
		for _, r := range a.GetRanges() {
			if r.GetRepo() == "" {
				continue
			}
			repo := strings.ToLower(r.GetRepo())
			ranges[repo] = append(ranges[repo], r)
			versions[repo] = append(versions[repo], a.GetVersions()...)
		}
	}

	return ranges, versions
}

// repoURLFromRanges returns the first repo URL from a GIT-type range, if present.
func repoURLFromRanges(ranges []*osvschema.Range) string {
	for _, r := range ranges {
		if r.GetType() == osvschema.Range_GIT && r.GetRepo() != "" {
			return r.GetRepo()
		}
	}

	return ""
}

const (
	maxRepoPURLTags = 200
	repoPURLsKey    = "repo_purls"
)

// enrichRepoPURLs populates repo-derived pURLs on each affected entry that
// has a GIT-type range: an unversioned pkg:generic purl on
// affected.package.purl (when unset), and a list of versioned variants under
// affected.database_specific["repo_purls"].
func enrichRepoPURLs(v *osvschema.Vulnerability) {
	if v == nil || len(v.GetAffected()) == 0 {
		return
	}
	for _, aff := range v.Affected {
		repo := repoURLFromRanges(aff.GetRanges())
		if repo == "" {
			continue
		}
		tmpl, err := gitpurl.ParseRepoPURL(repo)
		if err != nil {
			continue
		}

		if aff.Package == nil {
			aff.Package = &osvschema.Package{}
		}
		if aff.Package.Purl == "" {
			aff.Package.Purl = tmpl.ToString()
		}

		addVersionedRepoPURLs(aff, tmpl)
	}
}

// addVersionedRepoPURLs attaches one versioned pkg:generic/...@<tag> entry
// under affected.database_specific[repoPURLsKey] per entry in aff.Versions.
func addVersionedRepoPURLs(aff *osvschema.Affected, tmpl *packageurl.PackageURL) {
	if len(aff.Versions) == 0 {
		return
	}

	tags := aff.Versions[:min(len(aff.Versions), maxRepoPURLTags)]

	versionedPURLs := make([]any, 0, len(tags))
	for _, t := range tags {
		if t == "" {
			continue
		}
		tmpl.Version = t
		versionedPURLs = append(versionedPURLs, tmpl.ToString())
	}
	if len(versionedPURLs) == 0 {
		return
	}

	if aff.DatabaseSpecific == nil {
		ds, err := utility.NewStructpbFromMap(nil)
		if err != nil {
			return
		}
		aff.DatabaseSpecific = ds
	}
	if err := conversion.AddFieldToDatabaseSpecific(aff.DatabaseSpecific, repoPURLsKey, versionedPURLs); err != nil {
		return
	}
}
