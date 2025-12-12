package cvelist2osv

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

// TestSnapshotConversion runs the conversion process on a sample of CVEs and
// creates snapshots of the output for comparison. This is used for monitoring
// progressions and regressions when making changes to the converter.
func TestSnapshotConversion(t *testing.T) {
	testDataDir := "testdata/sampled_cves"
	files, err := os.ReadDir(testDataDir)
	if err != nil {
		t.Fatalf("Failed to read test data directory: %v", err)
	}

	stats := make(map[string]int)
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			path := filepath.Join(testDataDir, file.Name())
			cve := loadTestCVE(t, path)

			vWriter := bytes.NewBuffer(nil)
			mWriter := bytes.NewBuffer(nil)

			// We use a fixed source link for stability in snapshots if it's used in output
			sourceLink := "https://github.com/CVEProject/cvelistV5/tree/main/cves/..."

			outcome, err := ConvertAndExportCVEToOSV(cve, vWriter, mWriter, sourceLink)
			if err != nil {
				t.Errorf("ConvertAndExportCVEToOSV failed: %v", err)
			}
			stats[outcome.String()]++

			// Normalize the output for snapshot stability if necessary
			// For now, we assume ConvertAndExportCVEToOSV produces deterministic output
			// given the same input and source link.

			cna := cve.Metadata.AssignerShortName
			if cna == "" {
				cna = "unknown"
			}
			// Sanitize CNA name for filename
			cna = strings.ReplaceAll(cna, "/", "_")
			cna = strings.ReplaceAll(cna, "\\", "_")

			snaps.WithConfig(snaps.Filename("cna-snaps/"+cna)).MatchSnapshot(t, vWriter.String())
		})
	}

	// Sort keys for deterministic output
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var statsOutput strings.Builder
	statsOutput.WriteString("Conversion Outcomes:\n")
	for _, k := range keys {
		statsOutput.WriteString(fmt.Sprintf("%s: %d\n", k, stats[k]))
	}
	snaps.WithConfig(snaps.Filename("conversion_outcomes")).MatchSnapshot(t, statsOutput.String())
}
