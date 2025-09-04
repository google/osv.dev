package main

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func mustRead(tb testing.TB, filename string) []byte {
	tb.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		tb.Fatalf("Failed to read file %s: %v", filename, err)
	}

	return data
}

// sortAffected is a helper to sort affected packages for consistent comparison.
func sortAffected(affected []osvschema.Affected) {
	sort.Slice(affected, func(i, j int) bool {
		if affected[i].Package.Name != affected[j].Package.Name {
			return affected[i].Package.Name < affected[j].Package.Name
		}

		return affected[i].Package.Ecosystem < affected[j].Package.Ecosystem
	})
}

func TestGenerateOSVFromDebianTracker(t *testing.T) {
	// Mock the time
	now := time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)

	var trackerData DebianSecurityTrackerData
	if err := json.Unmarshal(mustRead(t, "../../test_data/debian/debian_security_tracker_mock.json"), &trackerData); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	releaseMap := map[string]string{
		"sarge":    "3.1",
		"stretch":  "9",
		"buster":   "10",
		"bullseye": "11",
		"bookworm": "12",
		"trixie":   "13",
	}

	got := generateOSVFromDebianTracker(trackerData, releaseMap)

	// Define the expected OSV entries.
	want := map[string]*vulns.Vulnerability{
		"CVE-2018-1000500": {
			Vulnerability: osvschema.Vulnerability{
				ID:       "DEBIAN-CVE-2018-1000500",
				Upstream: []string{"CVE-2018-1000500"},
				Modified: now,
				Details:  "Busybox contains a Missing SSL certificate validation vulnerability in The \"busybox wget\" applet that can result in arbitrary code execution. This attack appear to be exploitable via Simply download any file over HTTPS using \"busybox wget https://compromised-domain.com/important-file\".",
				Affected: []osvschema.Affected{
					{Package: osvschema.Package{Name: "busybox", Ecosystem: "Debian:10"}, EcosystemSpecific: map[string]any{"urgency": "end-of-life"}},
					{Package: osvschema.Package{Name: "busybox", Ecosystem: "Debian:11"}, EcosystemSpecific: map[string]any{"urgency": "unimportant"}},
					{Package: osvschema.Package{Name: "busybox", Ecosystem: "Debian:12"}, EcosystemSpecific: map[string]any{"urgency": "unimportant"}},
					{Package: osvschema.Package{Name: "busybox", Ecosystem: "Debian:13"}, EcosystemSpecific: map[string]any{"urgency": "unimportant"}},
				},
				References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/CVE-2018-1000500"}},
			},
		},
		"CVE-2014-1424": {
			Vulnerability: osvschema.Vulnerability{
				ID:         "DEBIAN-CVE-2014-1424",
				Upstream:   []string{"CVE-2014-1424"},
				Modified:   now,
				Details:    "apparmor_parser in the apparmor package before 2.8.95~2430-0ubuntu5.1 in Ubuntu 14.04 allows attackers to bypass AppArmor policies via unspecified vectors, related to a \"miscompilation flaw.\"",
				Affected:   nil, // Empty because all are resolved at version "0"
				References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/CVE-2014-1424"}},
			},
		},
		"CVE-2016-1585": {
			Vulnerability: osvschema.Vulnerability{
				ID:       "DEBIAN-CVE-2016-1585",
				Upstream: []string{"CVE-2016-1585"},
				Modified: now,
				Details:  "In all versions of AppArmor mount rules are accidentally widened when compiled.",
				Affected: []osvschema.Affected{
					{Package: osvschema.Package{Name: "apparmor", Ecosystem: "Debian:10"}, EcosystemSpecific: map[string]any{"urgency": "unimportant"}},
					{Package: osvschema.Package{Name: "apparmor", Ecosystem: "Debian:11"}, EcosystemSpecific: map[string]any{"urgency": "unimportant"}},
					{Package: osvschema.Package{Name: "apparmor", Ecosystem: "Debian:12"}, EcosystemSpecific: map[string]any{"urgency": "unimportant"}},
					{
						Package:           osvschema.Package{Name: "apparmor", Ecosystem: "Debian:13"},
						Ranges:            []osvschema.Range{{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "3.0.12-1"}}}},
						EcosystemSpecific: map[string]any{"urgency": "unimportant"},
					},
				},
				References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/CVE-2016-1585"}},
			},
		},
		"CVE-2017-6507": {
			Vulnerability: osvschema.Vulnerability{
				ID:       "DEBIAN-CVE-2017-6507",
				Upstream: []string{"CVE-2017-6507"},
				Modified: now,
				Details:  "An issue was discovered in AppArmor before 2.12. Incorrect handling of unknown AppArmor profiles in AppArmor init scripts, upstart jobs, and/or systemd unit files allows an attacker to possibly have increased attack surfaces of processes that were intended to be confined by AppArmor. This is due to the common logic to handle 'restart' operations removing AppArmor profiles that aren't found in the typical filesystem locations, such as /etc/apparmor.d/. Userspace projects that manage their own AppArmor profiles in atypical directories, such as what's done by LXD and Docker, are affected by this flaw in the AppArmor init script logic.",
				Affected: []osvschema.Affected{
					{
						Package:           osvschema.Package{Name: "apparmor", Ecosystem: "Debian:10"},
						Ranges:            []osvschema.Range{{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.11.0-3"}}}},
						EcosystemSpecific: map[string]any{"urgency": "not yet assigned"},
					},
					{
						Package:           osvschema.Package{Name: "apparmor", Ecosystem: "Debian:11"},
						Ranges:            []osvschema.Range{{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.11.0-3"}}}},
						EcosystemSpecific: map[string]any{"urgency": "not yet assigned"},
					},
					{
						Package:           osvschema.Package{Name: "apparmor", Ecosystem: "Debian:12"},
						Ranges:            []osvschema.Range{{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.11.0-3"}}}},
						EcosystemSpecific: map[string]any{"urgency": "not yet assigned"},
					},
					{
						Package:           osvschema.Package{Name: "apparmor", Ecosystem: "Debian:13"},
						Ranges:            []osvschema.Range{{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.11.0-3"}}}},
						EcosystemSpecific: map[string]any{"urgency": "not yet assigned"},
					},
				},
				References: []osvschema.Reference{{Type: "ADVISORY", URL: "https://security-tracker.debian.org/tracker/CVE-2017-6507"}},
			},
		},
	}

	if len(got) != len(want) {
		t.Fatalf("generateOSVFromDebianTracker() returned %d CVEs, want %d", len(got), len(want))
	}

	for cveID, wantVuln := range want {
		gotVuln, ok := got[cveID]
		if !ok {
			t.Errorf("generateOSVFromDebianTracker() missing expected CVE %s", cveID)
			continue
		}

		// Ignore Modified time for comparison.
		wantVuln.Modified = gotVuln.Modified

		// Sort affected packages for consistent comparison.
		sortAffected(gotVuln.Affected)
		sortAffected(wantVuln.Affected)

		if diff := cmp.Diff(wantVuln, gotVuln); diff != "" {
			t.Errorf("OSV for %s mismatch (-want +got):\n%s", cveID, diff)
		}
	}
}
