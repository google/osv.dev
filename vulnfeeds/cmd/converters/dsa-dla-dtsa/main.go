// Package main provides a converter for Debian Security Advisories (DSA, DLA, DTSA) to OSV format.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
	"github.com/google/osv/vulnfeeds/conversion/writer"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/text/encoding/charmap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	webwmlSecurityPath      = "english/security"
	webwmlLtsSecurityPath   = "english/lts/security"
	securityTrackerDsaPath  = "data/DSA/list"
	securityTrackerDtsaPath = "data/DTSA/list"
	securityTrackerDlaPath  = "data/DLA/list"
	debianBaseURL           = "https://www.debian.org"
	notAffectedVersion      = "<not-affected>"
	unfixedVersion          = "<unfixed>"
	endOfLifeVersion        = "<end-of-life>"
	gitDatePrefix           = "-----" // Prefix used to identify a new date line
)

var (
	leadingWhitespacePattern = regexp.MustCompile(`^\s`)
	dsaPattern               = regexp.MustCompile(`\[(.*?)]\s*([\w-]+)\s*(.*)`)                  // e.g. [25 Apr 2022] DSA-5124-1 ffmpeg - security update
	versionPattern           = regexp.MustCompile(`\[(.*?)]\s*-\s*([^\s]+)\s*([^\s]+)`)          // e.g. [buster] - xz-utils 5.2.4-1+deb10u1
	wmlDescriptionPattern    = regexp.MustCompile(`(?s)<define-tag moreinfo>(.*?)</define-tag>`) // e.g. <define-tag moreinfo>\n Some html here \n</define-tag>
	wmlReportDatePattern     = regexp.MustCompile(`<define-tag report_date>(.*?)</define-tag>`)  // e.g. <define-tag report_date>2022-1-04</define-tag>
	dsaOrDlaWithNoExtPattern = regexp.MustCompile(`d[sl]a-\d+`)                                  // e.g. DSA-12345-2, -2 is the extension
)

type AdvisoryType string

const (
	AdvisoryTypeDSA  AdvisoryType = "DSA"
	AdvisoryTypeDLA  AdvisoryType = "DLA"
	AdvisoryTypeDTSA AdvisoryType = "DTSA"
)

type AffectedInfo struct {
	Package              string
	Fixed                string
	DebianReleaseVersion string
}

type AdvisoryInfo struct {
	ID         string
	Summary    string
	Details    string
	Published  time.Time
	Modified   time.Time
	Affected   []AffectedInfo
	Upstream   []string
	References []*osvschema.Reference
}

type Advisories map[string]*AdvisoryInfo

func createCodenameToVersion() (map[string]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://debian.pages.debian.net/distro-info-data/debian.csv")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, errors.New("empty csv")
	}

	headers := records[0]
	seriesIdx := -1
	versionIdx := -1
	for i, h := range headers {
		if h == "series" {
			seriesIdx = i
		}
		if h == "version" {
			versionIdx = i
		}
	}

	if seriesIdx == -1 || versionIdx == -1 {
		return nil, errors.New("missing series or version column")
	}

	result := make(map[string]string)
	for _, row := range records[1:] {
		result[row[seriesIdx]] = row[versionIdx]
	}
	result["sid"] = "unstable"

	return result, nil
}

func parseSecurityTrackerFile(advisories Advisories, securityTrackerRepo, securityTrackerPath string) error {
	codenameToVersion, err := createCodenameToVersion()
	if err != nil {
		return err
	}

	file, err := os.Open(filepath.Join(securityTrackerRepo, securityTrackerPath))
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentAdvisory string

	// Enumerate advisories + version info from security-tracker.
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t\r\n")
		if line == "" {
			continue
		}

		if leadingWhitespacePattern.MatchString(line) {
			if currentAdvisory == "" {
				return errors.New("unexpected tab")
			}

			line = strings.TrimLeft(line, " \t")
			if strings.HasPrefix(line, "{") {
				upstreams := strings.Fields(strings.Trim(line, "{}"))
				for _, u := range upstreams {
					// This is not ideal, in the cases that there are missing
					// Debian Security Tracker CVEs, but it's better than not having them
					advisories[currentAdvisory].Upstream = append(advisories[currentAdvisory].Upstream, "DEBIAN-"+u)
					advisories[currentAdvisory].Upstream = append(advisories[currentAdvisory].Upstream, u)
				}

				continue
			}

			if strings.HasPrefix(line, "NOTE:") {
				continue
			}

			versionMatch := versionPattern.FindStringSubmatch(line)
			if versionMatch == nil {
				return fmt.Errorf("invalid version line: %s", line)
			}

			releaseName := versionMatch[1]
			packageName := versionMatch[2]
			fixedVer := versionMatch[3]

			// Only create advisory if the version is affected.
			if fixedVer != notAffectedVersion {
				// If fixed version is one of the following special values
				// fixed version essentially doesn't exist, so blank it
				if fixedVer == unfixedVersion || fixedVer == endOfLifeVersion {
					fixedVer = ""
				}
				advisories[currentAdvisory].Affected = append(advisories[currentAdvisory].Affected, AffectedInfo{
					DebianReleaseVersion: codenameToVersion[releaseName],
					Package:              packageName,
					Fixed:                fixedVer,
				})
			}
		} else {
			if strings.HasPrefix(strings.TrimSpace(line), "NOTE:") {
				continue
			}

			dsaMatch := dsaPattern.FindStringSubmatch(line)
			if dsaMatch == nil {
				return fmt.Errorf("invalid line: %s", line)
			}

			parsedDate, err := time.Parse(time.RFC1123Z, dsaMatch[1])
			if err != nil {
				// Fallback to the old format just in case
				parsedDate, err = time.Parse("02 Jan 2006", dsaMatch[1])
				if err != nil {
					// Fallback for DTSA format like "August 26th, 2005"
					cleanDate := strings.ReplaceAll(dsaMatch[1], "st,", ",")
					cleanDate = strings.ReplaceAll(cleanDate, "nd,", ",")
					cleanDate = strings.ReplaceAll(cleanDate, "rd,", ",")
					cleanDate = strings.ReplaceAll(cleanDate, "th,", ",")
					parsedDate, err = time.Parse("January 2, 2006", cleanDate)
					if err != nil {
						return fmt.Errorf("invalid date: %s", dsaMatch[1])
					}
				}
			}

			currentAdvisory = dsaMatch[2]
			advisories[currentAdvisory] = &AdvisoryInfo{
				ID:        currentAdvisory,
				Summary:   dsaMatch[3],
				Published: parsedDate,
				Modified:  parsedDate,
			}
		}
	}

	return scanner.Err()
}

func parseWebwmlFiles(advisories Advisories, webwmlRepoPath, wmlFileSubPath string) error {
	filePathMap := make(map[string]string)

	err := filepath.WalkDir(filepath.Join(webwmlRepoPath, wmlFileSubPath), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			filePathMap[d.Name()] = path
		}

		return nil
	})
	if err != nil {
		return err
	}

	gitRelativePaths := make(map[string][]string)

	// Add descriptions to advisories from wml files
	for dsaID, advisory := range advisories {
		// Remove potential extension (e.g. DSA-12345-2, -2 is the extension)
		matches := dsaOrDlaWithNoExtPattern.FindAllString(strings.ToLower(dsaID), -1)
		if len(matches) == 0 {
			continue
		}
		mappedKeyNoExt := matches[0]

		wmlPath, wmlOk := filePathMap[mappedKeyNoExt+".wml"]
		dataPath, dataOk := filePathMap[mappedKeyNoExt+".data"]

		if !wmlOk {
			// logger.Info("No WML file yet for this, creating partial schema", "dsaID", mappedKeyNoExt)
			continue
		}

		wmlBytes, err := os.ReadFile(wmlPath)
		if err != nil {
			return err
		}

		decoder := charmap.ISO8859_2.NewDecoder()
		wmlData, err := decoder.Bytes(wmlBytes)
		if err != nil {
			return err
		}

		htmlMatches := wmlDescriptionPattern.FindAllStringSubmatch(string(wmlData), -1)
		if len(htmlMatches) > 0 {
			res, err := htmltomarkdown.ConvertString(htmlMatches[0][1])
			if err == nil {
				advisory.Details = res
			}
		}

		if dataOk {
			dataBytes, err := os.ReadFile(dataPath)
			if err != nil {
				return err
			}
			reportDateMatches := wmlReportDatePattern.FindAllStringSubmatch(string(dataBytes), -1)
			// Split by ',' here for the occasional case where there
			// are two dates in the 'publish' field.
			// Multiple dates are caused by major modification later on.
			// This is accounted for with the modified timestamp with git
			// below though, so we don't need to parse them here
			if len(reportDateMatches) > 0 {
				reportDateStr := strings.Split(reportDateMatches[0][1], ",")[0]
				parsedDate, err := time.Parse("2006-1-02", reportDateStr)
				if err == nil {
					advisory.Published = parsedDate
				}
			}
		}

		relWmlPath, _ := filepath.Rel(filepath.Join(webwmlRepoPath, "english"), wmlPath)
		advisoryURLPath := strings.TrimSuffix(relWmlPath, filepath.Ext(relWmlPath))
		advisoryURL := fmt.Sprintf("%s/%s", debianBaseURL, advisoryURLPath)

		advisory.References = append(advisory.References, &osvschema.Reference{
			Type: osvschema.Reference_ADVISORY,
			Url:  advisoryURL,
		})

		gitRelWmlPath, _ := filepath.Rel(webwmlRepoPath, wmlPath)
		gitRelDataPath, _ := filepath.Rel(webwmlRepoPath, dataPath)
		gitRelativePaths[gitRelWmlPath] = append(gitRelativePaths[gitRelWmlPath], dsaID)
		gitRelativePaths[gitRelDataPath] = append(gitRelativePaths[gitRelDataPath], dsaID)
	}

	modifiedDateDict := make(map[string]time.Time)

	//nolint:gosec // gitDatePrefix is a constant
	cmd := exec.Command("git", "log", fmt.Sprintf("--pretty=%s%%aI", gitDatePrefix), "--name-only", "--author-date-order")
	cmd.Dir = webwmlRepoPath
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	var currentDate time.Time
	// Loop through each commit to get the first time a file is mentioned
	// Save the date as the last modified date of said file
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, gitDatePrefix) {
			parsedDate, err := time.Parse(time.RFC3339, line[len(gitDatePrefix):])
			if err == nil {
				currentDate = parsedDate.UTC()
			}

			continue
		}

		dsaIDs, ok := gitRelativePaths[line]
		if !ok {
			continue
		}

		for _, dsaID := range dsaIDs {
			// Set modified date to the latest of the .data and .wml files.
			if currentDate.After(modifiedDateDict[dsaID]) {
				modifiedDateDict[dsaID] = currentDate
			}
		}
		delete(gitRelativePaths, line)
		// Empty dictionary means no more files need modification dates
		// Safely skip rest of the commits
		if len(gitRelativePaths) == 0 {
			break
		}
	}

	// ignore wait error as we might have broken the pipe early
	_ = cmd.Wait()

	for dsaID, modifiedDate := range modifiedDateDict {
		if !modifiedDate.IsZero() {
			advisories[dsaID].Modified = modifiedDate
		}
	}

	return nil
}

func generateVulnerabilities(advisories Advisories) ([]*osvschema.Vulnerability, error) {
	vulnerabilities := make([]*osvschema.Vulnerability, 0, len(advisories))
	for dsaID, advisory := range advisories {
		if len(advisory.Affected) == 0 {
			logger.Info("Skipping because no affected versions", "dsaID", dsaID)
			continue
		}

		osv := &osvschema.Vulnerability{
			Id:        dsaID,
			Summary:   advisory.Summary,
			Details:   advisory.Details,
			Published: timestamppb.New(advisory.Published),
			Modified:  timestamppb.New(advisory.Modified),
		}

		if len(advisory.Upstream) > 0 {
			osv.Upstream = append(osv.Upstream, advisory.Upstream...)
		}

		for _, ref := range advisory.References {
			osv.References = append(osv.References, &osvschema.Reference{
				Type: ref.GetType(),
				Url:  ref.GetUrl(),
			})
		}

		for _, aff := range advisory.Affected {
			affected := &osvschema.Affected{
				Package: &osvschema.Package{
					Ecosystem: "Debian:" + aff.DebianReleaseVersion,
					Name:      aff.Package,
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "0"},
						},
					},
				},
			}
			if aff.Fixed != "" {
				affected.Ranges[0].Events = append(affected.Ranges[0].Events, &osvschema.Event{
					Fixed: aff.Fixed,
				})
			}
			osv.Affected = append(osv.Affected, affected)
		}

		vulnerabilities = append(vulnerabilities, osv)
	}

	return vulnerabilities, nil
}

func convertDebian(webwmlRepo, securityTrackerRepo string, advType AdvisoryType) ([]*osvschema.Vulnerability, error) {
	advisories := make(Advisories)

	switch advType {
	case AdvisoryTypeDLA:
		if err := parseSecurityTrackerFile(advisories, securityTrackerRepo, securityTrackerDlaPath); err != nil {
			return nil, err
		}
		if err := parseWebwmlFiles(advisories, webwmlRepo, webwmlLtsSecurityPath); err != nil {
			return nil, err
		}
	case AdvisoryTypeDSA:
		if err := parseSecurityTrackerFile(advisories, securityTrackerRepo, securityTrackerDsaPath); err != nil {
			return nil, err
		}
		if err := parseWebwmlFiles(advisories, webwmlRepo, webwmlSecurityPath); err != nil {
			return nil, err
		}
	case AdvisoryTypeDTSA:
		if err := parseSecurityTrackerFile(advisories, securityTrackerRepo, securityTrackerDtsaPath); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid advisory type")
	}

	return generateVulnerabilities(advisories)
}

func cloneRepo(url, dest string) error {
	logger.Info("Cloning repository", "url", url, "dest", dest)

	cmd := exec.Command("git", "clone", "--quiet", url, dest, "--depth=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	outputDir := flag.String("o", "", "Output directory")
	webwmlRepo := flag.String("webwml", "", "Webwml repository")
	securityTrackerRepo := flag.String("security-tracker", "", "Security tracker repository")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "Upload to GCS")
	outputBucket := flag.String("output-bucket", "debian-osv", "Output bucket")
	numWorkers := flag.Int("num-workers", 10, "Number of workers")
	doDeletions := flag.Bool("do-deletions", false, "Do deletions")

	flag.Parse()

	if *outputDir == "" {
		logger.Error("Output directory is required")
		logger.Close()
		os.Exit(1) //nolint:gocritic
	}

	if err := run(*webwmlRepo, *securityTrackerRepo, *outputDir, *outputBucket, *uploadToGCS, *doDeletions, *numWorkers); err != nil {
		logger.Error("Execution failed", "err", err)
		logger.Close()
		os.Exit(1)
	}
}

func run(webwmlRepo, securityTrackerRepo, outputDir, outputBucket string, uploadToGCS, doDeletions bool, numWorkers int) error {
	if webwmlRepo == "" {
		tempDir, err := os.MkdirTemp("", "webwml-*")
		if err != nil {
			return fmt.Errorf("failed to create temp dir for webwml: %w", err)
		}
		defer os.RemoveAll(tempDir)
		if err := cloneRepo("https://salsa.debian.org/webmaster-team/webwml.git", tempDir); err != nil {
			return fmt.Errorf("failed to clone webwml: %w", err)
		}
		webwmlRepo = tempDir
	}

	if securityTrackerRepo == "" {
		tempDir, err := os.MkdirTemp("", "security-tracker-*")
		if err != nil {
			return fmt.Errorf("failed to create temp dir for security-tracker: %w", err)
		}
		defer os.RemoveAll(tempDir)
		if err := cloneRepo("https://salsa.debian.org/security-tracker-team/security-tracker.git", tempDir); err != nil {
			return fmt.Errorf("failed to clone security-tracker: %w", err)
		}
		securityTrackerRepo = tempDir
	}

	advisoryTypes := []AdvisoryType{AdvisoryTypeDSA, AdvisoryTypeDLA, AdvisoryTypeDTSA}
	var allVulnerabilities []*osvschema.Vulnerability

	for _, advType := range advisoryTypes {
		logger.Info("Converting advisories", "type", advType)

		vulns, err := convertDebian(webwmlRepo, securityTrackerRepo, advType)
		if err != nil {
			return fmt.Errorf("error converting type %s: %w", advType, err)
		}

		allVulnerabilities = append(allVulnerabilities, vulns...)

		if !uploadToGCS {
			advOutputDir := filepath.Join(outputDir, strings.ToLower(string(advType)))
			if err := os.MkdirAll(advOutputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output dir %s: %w", advOutputDir, err)
			}

			for _, vuln := range vulns {
				b, err := protojson.Marshal(vuln)
				if err != nil {
					logger.Error("Failed to marshal vulnerability", "id", vuln.GetId(), "err", err)
					continue
				}
				var buf bytes.Buffer
				if err := json.Indent(&buf, b, "", "  "); err != nil {
					logger.Error("Failed to indent vulnerability", "id", vuln.GetId(), "err", err)
					continue
				}
				outPath := filepath.Join(advOutputDir, vuln.GetId()+".json")
				//nolint:gosec // 0644 is fine for public vulnerability data
				if err := os.WriteFile(outPath, b, 0644); err != nil {
					logger.Error("Failed to write vulnerability", "id", vuln.GetId(), "err", err)
					continue
				}
				logger.Info("Writing", "path", outPath)
			}
		}
	}

	if uploadToGCS {
		logger.Info("Uploading to GCS", "bucket", outputBucket)
		ctx := context.Background()
		writer.UploadVulnsToGCS(ctx, "debian-osv", uploadToGCS, outputBucket, "", numWorkers, outputDir, allVulnerabilities, doDeletions)
	} else {
		logger.Info("Skipping GCS upload")
	}

	return nil
}
