package linter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv.dev/go/internal/linter"
	"go.yaml.in/yaml/v4"
)

func TestDefaultRegistry_SourcesExistInSourceYAML(t *testing.T) {
	t.Parallel()

	reg, err := linter.LoadFile("suppressions.yaml")
	if err != nil {
		t.Fatalf("failed loading suppressions.yaml: %v", err)
	}
	suppressionSources := reg.Sources()
	if len(suppressionSources) == 0 {
		t.Fatal("expected at least one suppression source in suppressions.yaml")
	}

	knownSources := make(map[string]bool)
	for _, relPath := range []string{
		filepath.Join("..", "..", "..", "source.yaml"),
		filepath.Join("..", "..", "..", "source_test.yaml"),
	} {
		data, err := os.ReadFile(relPath)
		if err != nil {
			t.Fatalf("failed reading %s: %v", relPath, err)
		}
		var entries []struct {
			Name string `yaml:"name"`
		}
		if err := yaml.Load(data, &entries); err != nil {
			t.Fatalf("failed parsing %s: %v", relPath, err)
		}
		if len(entries) == 0 {
			t.Fatalf("expected non-empty source list in %s", relPath)
		}
		for _, e := range entries {
			if e.Name != "" {
				knownSources[e.Name] = true
			}
		}
	}

	for _, src := range suppressionSources {
		if !knownSources[src] {
			t.Errorf("suppression rule references unknown source %q not found in source.yaml or source_test.yaml", src)
		}
	}
}

func TestDefaultRegistry_BuiltInRules(t *testing.T) {
	t.Parallel()
	reg := linter.DefaultRegistry()

	if reason, ok := reg.Match("chainguard", "CGA-2222-7w6m-pmh8", "RNG:002", `overlapping event: "0"`); !ok || reason == "" {
		t.Fatalf("expected chainguard RNG:002 overlapping event \"0\" to be suppressed, got ok=%v reason=%q", ok, reason)
	}
	for _, bugID := range []string{"SUSE-SU-2024:0123-1", "openSUSE-SU-2024:0456-1"} {
		if reason, ok := reg.Match("suse", bugID, "REC:003", "Invalid Upstream: upstream should not contain related IDs"); !ok || reason == "" {
			t.Fatalf("expected suse REC:003 (%s) to be suppressed, got ok=%v reason=%q", bugID, ok, reason)
		}
	}

	for _, tc := range []struct {
		name    string
		source  string
		bugID   string
		code    string
		message string
	}{
		{
			name:    "non-zero overlapping event on chainguard is not suppressed",
			source:  "chainguard",
			bugID:   "CGA-2222-7w6m-pmh8",
			code:    "RNG:002",
			message: `overlapping event: "1.2.3"`,
		},
		{
			name:    "other rule code on chainguard is not suppressed",
			source:  "chainguard",
			bugID:   "CGA-2222-7w6m-pmh8",
			code:    "RNG:001",
			message: `overlapping event: "0"`,
		},
		{
			name:    "overlapping zero on other source is not suppressed",
			source:  "ghsa",
			bugID:   "GHSA-1234-5678-9012",
			code:    "RNG:002",
			message: `overlapping event: "0"`,
		},
		{
			name:    "other REC:003 message on suse is not suppressed",
			source:  "suse",
			bugID:   "SUSE-SU-2024:0123-1",
			code:    "REC:003",
			message: "Invalid Upstream: upstream should not contain itself",
		},
		{
			name:    "upstream related message on other source is not suppressed",
			source:  "ghsa",
			bugID:   "GHSA-1234-5678-9012",
			code:    "REC:003",
			message: "Invalid Upstream: upstream should not contain related IDs",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if gotReason, gotOK := reg.Match(tc.source, tc.bugID, tc.code, tc.message); gotOK {
				t.Errorf("expected no match, got reason=%q", gotReason)
			}
		})
	}
}

func TestParseConfigAndLoadFile(t *testing.T) {
	t.Parallel()

	var nilReg *linter.Registry
	if _, ok := nilReg.Match("chainguard", "CGA-1", "RNG:002", `overlapping event: "0"`); ok {
		t.Fatal("nil Registry should never match")
	}
	if sources := nilReg.Sources(); sources != nil {
		t.Fatalf("nil Registry Sources() = %v, want nil", sources)
	}

	emptyReg, err := linter.ParseConfig([]byte("   \n"))
	if err != nil {
		t.Fatalf("expected empty config to succeed, got %v", err)
	}
	if _, ok := emptyReg.Match("chainguard", "CGA-1", "RNG:002", `overlapping event: "0"`); ok {
		t.Fatal("empty Registry should not match")
	}

	commentOnlyReg, err := linter.ParseConfig([]byte("# Only comments here\n# suppressions: []\n"))
	if err != nil {
		t.Fatalf("expected comment-only config to succeed, got %v", err)
	}
	if _, ok := commentOnlyReg.Match("chainguard", "CGA-1", "RNG:002", `overlapping event: "0"`); ok {
		t.Fatal("comment-only Registry should not match")
	}

	yamlCfg := `
suppressions:
  - source: custom-db
    code: sch:001
    message_regex: 'references\.\d+\.url'
    bug_id_regex: '^CUSTOM-2024-'
    reason: 'Legacy 2024 reference format accepted'
`
	tmpFile := filepath.Join(t.TempDir(), "suppressions.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlCfg), 0600); err != nil {
		t.Fatalf("failed writing temp yaml: %v", err)
	}

	reg, err := linter.LoadFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	if reason, ok := reg.Match("custom-db", "CUSTOM-2024-0001", "SCH:001", " - references.3.url: bad uri"); !ok || !strings.Contains(reason, "Legacy 2024") {
		t.Errorf("expected regex rule match, got ok=%v reason=%q", ok, reason)
	}
	if _, ok := reg.Match("custom-db", "CUSTOM-2025-0001", "SCH:001", " - references.3.url: bad uri"); ok {
		t.Error("expected bug_id_regex mismatch")
	}
	if _, ok := reg.Match("custom-db", "CUSTOM-2024-0001", "SCH:001", " - summary: invalid"); ok {
		t.Error("expected message_regex mismatch")
	}

	if _, err := linter.LoadFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}

	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"unknown yaml field", "suppressions:\n  - source: a\n    unknown: 1\n    reason: x\n"},
		{"missing source", "suppressions:\n  - code: RNG:002\n    reason: x\n"},
		{"missing reason", "suppressions:\n  - source: a\n    code: RNG:002\n"},
		{"no matchers", "suppressions:\n  - source: a\n    reason: x\n"},
		{"wildcard code disallowed", "suppressions:\n  - source: a\n    code: '*'\n    reason: x\n"},
		{"bad message_regex", "suppressions:\n  - source: a\n    message_regex: '['\n    reason: x\n"},
		{"bad bug_id_regex", "suppressions:\n  - source: a\n    bug_id_regex: '['\n    reason: x\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := linter.ParseConfig([]byte(tc.yaml)); err == nil {
				t.Errorf("expected ParseConfig error for %s, got nil", tc.name)
			}
		})
	}
}
