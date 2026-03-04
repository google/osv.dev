// Package main provides a converter for Debian Security Advisories (DSA, DLA, DTSA) to OSV format.
package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
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
	gitDatePrefix           = "-----"
)

var (
	leadingWhitespacePattern = regexp.MustCompile(`^\s`)
	dsaPattern               = regexp.MustCompile(`\[(.*?)]\s*([\w-]+)\s*(.*)`)
	versionPattern           = regexp.MustCompile(`\[(.*?)]\s*-\s*([^\s]+)\s*([^\s]+)`)
	wmlDescriptionPattern    = regexp.MustCompile(`(?s)<define-tag moreinfo>(.*?)</define-tag>`)
	wmlReportDatePattern     = regexp.MustCompile(`<define-tag report_date>(.*?)</define-tag>`)
	dsaOrDlaWithNoExtPattern = regexp.MustCompile(`d[sl]a-\d+`)
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

var marshaler = protojson.MarshalOptions{
	Multiline: true, // Enables multiline output
	Indent:    "  ", // Specifies the indentation string (e.g., two spaces)
}

func createCodenameToVersion() (map[string]string, error) {
	resp, err := http.Get("https://debian.pages.debian.net/distro-info-data/debian.csv")
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

			if fixedVer != notAffectedVersion {
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
					return fmt.Errorf("invalid date: %s", dsaMatch[1])
				}
			}
			slog.Info("Parsed date", "date", parsedDate)

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

	for dsaID, advisory := range advisories {
		matches := dsaOrDlaWithNoExtPattern.FindAllString(strings.ToLower(dsaID), -1)
		if len(matches) == 0 {
			continue
		}
		mappedKeyNoExt := matches[0]

		wmlPath, wmlOk := filePathMap[mappedKeyNoExt+".wml"]
		dataPath, dataOk := filePathMap[mappedKeyNoExt+".data"]

		if !wmlOk {
			// slog.Info("No WML file yet for this, creating partial schema", "dsaID", mappedKeyNoExt)
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
			if currentDate.After(modifiedDateDict[dsaID]) {
				modifiedDateDict[dsaID] = currentDate
			}
		}
		delete(gitRelativePaths, line)

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

func writeOutput(outputDir string, advisories Advisories) error {
	for dsaID, advisory := range advisories {
		if len(advisory.Affected) == 0 {
			slog.Info("Skipping because no affected versions", "dsaID", dsaID)
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

		b, err := marshaler.Marshal(osv)
		if err != nil {
			return err
		}

		outPath := filepath.Join(outputDir, dsaID+".json")
		//nolint:gosec // 0644 is fine for public vulnerability data
		if err := os.WriteFile(outPath, b, 0644); err != nil {
			return err
		}
		slog.Info("Writing", "path", outPath)
	}
	slog.Info("Complete")

	return nil
}

func convertDebian(webwmlRepo, securityTrackerRepo, outputDir string, advType AdvisoryType) error {
	advisories := make(Advisories)

	switch advType {
	case AdvisoryTypeDLA:
		if err := parseSecurityTrackerFile(advisories, securityTrackerRepo, securityTrackerDlaPath); err != nil {
			return err
		}
		if err := parseWebwmlFiles(advisories, webwmlRepo, webwmlLtsSecurityPath); err != nil {
			return err
		}
	case AdvisoryTypeDSA:
		if err := parseSecurityTrackerFile(advisories, securityTrackerRepo, securityTrackerDsaPath); err != nil {
			return err
		}
		if err := parseWebwmlFiles(advisories, webwmlRepo, webwmlSecurityPath); err != nil {
			return err
		}
	case AdvisoryTypeDTSA:
		if err := parseSecurityTrackerFile(advisories, securityTrackerRepo, securityTrackerDtsaPath); err != nil {
			return err
		}
	default:
		return errors.New("invalid advisory type")
	}

	return writeOutput(outputDir, advisories)
}

func main() {
	outputDir := flag.String("o", "", "Output directory")
	advTypeStr := flag.String("adv-type", "", "Advisory type (DSA, DLA, DTSA)")
	webwmlRepo := flag.String("webwml", "", "Webwml repository")
	securityTrackerRepo := flag.String("security-tracker", "", "Security tracker repository")

	flag.Parse()

	if *outputDir == "" {
		slog.Error("Output directory is required")
		os.Exit(1)
	}

	advType := AdvisoryType(*advTypeStr)
	if advType != AdvisoryTypeDSA && advType != AdvisoryTypeDLA && advType != AdvisoryTypeDTSA {
		slog.Error("Invalid advisory type", "type", *advTypeStr)
		os.Exit(1)
	}

	if err := convertDebian(*webwmlRepo, *securityTrackerRepo, *outputDir, advType); err != nil {
		slog.Error("Error", "err", err)
		os.Exit(1)
	}
}
