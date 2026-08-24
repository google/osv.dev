package conversion

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fsouza/fake-gcs-server/fakestorage"
	"github.com/google/go-cmp/cmp"
	gcs "github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuildVersionRange(t *testing.T) {
	tests := []struct {
		name    string
		intro   string
		lastAff string
		fixed   string
		want    *osvschema.Range
	}{
		{
			name:  "intro and fixed",
			intro: "1.0.0",
			fixed: "1.0.1",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.0.1"},
				},
			},
		},
		{
			name:    "intro and last_affected",
			intro:   "1.0.0",
			lastAff: "1.0.0",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
					{LastAffected: "1.0.0"},
				},
			},
		},
		{
			name:  "only intro",
			intro: "1.0.0",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
				},
			},
		},
		{
			name: "empty intro",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildVersionRange(tt.intro, tt.lastAff, tt.fixed)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("BuildVersionRange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMergeTwoRanges(t *testing.T) {
	tests := []struct {
		name    string
		range1  *osvschema.Range
		range2  *osvschema.Range
		want    *osvschema.Range
		wantErr bool
	}{
		{
			name: "Merge identical ranges",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				Events: []*osvschema.Event{
					{Fixed: "1.0.0"},
				},
			},
			want: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				Events: []*osvschema.Event{
					{Introduced: "0"},
					{Fixed: "1.0.0"},
				},
			},
		},
		{
			name: "Different repos should return nil and error",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo1",
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo2",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Different types should return nil and error",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Repo: "https://github.com/example/repo",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Merge with DatabaseSpecific",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"key1": structpb.NewStringValue("value1"),
					},
				},
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"key2": structpb.NewStringValue("value2"),
					},
				},
			},
			want: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"key1": structpb.NewStringValue("value1"),
						"key2": structpb.NewStringValue("value2"),
					},
				},
			},
		},
		{
			name: "Merge DatabaseSpecific lists",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"list": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{structpb.NewStringValue("item1")},
						}),
					},
				},
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"list": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{structpb.NewStringValue("item2")},
						}),
					},
				},
			},
			want: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"list": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{
								structpb.NewStringValue("item1"),
								structpb.NewStringValue("item2"),
							},
						}),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeTwoRanges(tt.range1, tt.range2)
			if (err != nil) != tt.wantErr {
				t.Errorf("MergeTwoRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("mergeTwoRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMergeDatabaseSpecificValues(t *testing.T) {
	tests := []struct {
		name    string
		val1    any
		val2    any
		want    any
		wantErr bool
	}{
		{
			name: "Merge lists",
			val1: []any{"a", "b"},
			val2: []any{"c", "d"},
			want: []any{"a", "b", "c", "d"},
		},
		{
			name: "List and string",
			val1: []any{"a", "b"},
			val2: "c",
			want: []any{"a", "b", "c"},
		},
		{
			name: "String and list",
			val1: "a",
			val2: []any{"b", "c"},
			want: []any{"a", "b", "c"},
		},
		{
			name: "Merge maps",
			val1: map[string]any{"key1": "value1"},
			val2: map[string]any{"key2": "value2"},
			want: map[string]any{"key1": "value1", "key2": "value2"},
		},
		{
			name: "Merge nested maps",
			val1: map[string]any{
				"nested": map[string]any{
					"key1": "value1",
				},
			},
			val2: map[string]any{
				"nested": map[string]any{
					"key2": "value2",
				},
			},
			want: map[string]any{
				"nested": map[string]any{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
		{
			name:    "Map and string mismatch",
			val1:    map[string]any{"key1": "value1"},
			val2:    "string",
			wantErr: true,
		},
		{
			name: "Merge same strings",
			val1: "value1",
			val2: "value1",
			want: "value1",
		},
		{
			name: "Merge different strings",
			val1: "value1",
			val2: "value2",
			want: []any{"value1", "value2"},
		},
		{
			name:    "String and int mismatch",
			val1:    "value1",
			val2:    123,
			wantErr: true,
		},
		{
			name: "Merge same ints",
			val1: 123,
			val2: 123,
			want: 123,
		},
		{
			name: "Merge different ints",
			val1: 123,
			val2: 456,
			want: []any{123, 456},
		},
		{
			name:    "Int and float64 mismatch",
			val1:    123,
			val2:    456.0,
			wantErr: true,
		},
		{
			name: "Merge lists of maps with duplicates",
			val1: []any{
				map[string]any{"introduced": "1.0"},
			},
			val2: []any{
				map[string]any{"introduced": "1.0"},
				map[string]any{"introduced": "2.0"},
			},
			want: []any{
				map[string]any{"introduced": "1.0"},
				map[string]any{"introduced": "2.0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeDatabaseSpecificValues(tt.val1, tt.val2)
			if (err != nil) != tt.wantErr {
				t.Errorf("MergeDatabaseSpecificValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !cmp.Equal(got, tt.want) {
				t.Errorf("MergeDatabaseSpecificValues() mismatch (-want +got):\n%s", cmp.Diff(tt.want, got))
			}
		})
	}
}

func TestCreateUnresolvedRanges(t *testing.T) {
	tests := []struct {
		name  string
		input []models.RangeWithMetadata
		want  *structpb.ListValue
	}{
		{
			name:  "Empty ranges",
			input: []models.RangeWithMetadata{},
			want:  nil,
		},
		{
			name: "Multiple ranges with different sources and CPEs, sorted and grouped correctly",
			input: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Events: []*osvschema.Event{
							{Introduced: "1.0"},
						},
					},
					Metadata: models.Metadata{
						Source: models.VersionSourceDescription,
						CPE:    "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
					},
				},
				{
					Range: &osvschema.Range{
						Events: []*osvschema.Event{
							{Fixed: "2.0"},
						},
					},
					Metadata: models.Metadata{
						Source: models.VersionSourceCPE,
						CPE:    "cpe:2.3:a:another:app:*:*:*:*:*:*:*:*",
					},
				},
			},
			want: &structpb.ListValue{
				Values: []*structpb.Value{
					{
						Kind: &structpb.Value_StructValue{
							StructValue: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"vendor_product": structpb.NewStringValue("another:app"),
									"source":         structpb.NewStringValue(string(models.VersionSourceCPE)),
									"cpes": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("cpe:2.3:a:another:app:*:*:*:*:*:*:*:*"),
										},
									}),
									"extracted_events": {
										Kind: &structpb.Value_ListValue{
											ListValue: &structpb.ListValue{
												Values: []*structpb.Value{
													{
														Kind: &structpb.Value_StructValue{
															StructValue: &structpb.Struct{
																Fields: map[string]*structpb.Value{
																	"fixed": structpb.NewStringValue("2.0"),
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						Kind: &structpb.Value_StructValue{
							StructValue: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"vendor_product": structpb.NewStringValue("example:app"),
									"source":         structpb.NewStringValue(string(models.VersionSourceDescription)),
									"cpes": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("cpe:2.3:a:example:app:*:*:*:*:*:*:*:*"),
										},
									}),
									"extracted_events": {
										Kind: &structpb.Value_ListValue{
											ListValue: &structpb.ListValue{
												Values: []*structpb.Value{
													{
														Kind: &structpb.Value_StructValue{
															StructValue: &structpb.Struct{
																Fields: map[string]*structpb.Value{
																	"introduced": structpb.NewStringValue("1.0"),
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CreateUnresolvedRanges(tt.input)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("CreateUnresolvedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConductAnalysisAndUpload(t *testing.T) {
	tempBase := t.TempDir()
	metricsDir := filepath.Join(tempBase, "metrics")
	csvDir := filepath.Join(tempBase, "outcomes")

	if err := os.MkdirAll(filepath.Join(metricsDir, "2024"), 0755); err != nil {
		t.Fatalf("Failed to create metrics directory: %v", err)
	}

	metrics1 := models.ConversionMetrics{
		CVEID:   "CVE-2024-0001",
		Outcome: models.Successful,
	}
	metrics2 := models.ConversionMetrics{
		CVEID:   "CVE-2024-0002",
		Outcome: models.NoCommitRanges,
	}

	data1, err := json.Marshal(metrics1)
	if err != nil {
		t.Fatalf("Failed to marshal metrics1: %v", err)
	}
	data2, err := json.Marshal(metrics2)
	if err != nil {
		t.Fatalf("Failed to marshal metrics2: %v", err)
	}

	if err := os.WriteFile(filepath.Join(metricsDir, "2024", "CVE-2024-0001.metrics.json"), data1, 0600); err != nil {
		t.Fatalf("Failed to write metrics file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(metricsDir, "CVE-2024-0002.metrics.json"), data2, 0600); err != nil {
		t.Fatalf("Failed to write metrics file: %v", err)
	}

	t.Run("Separate csvDir and metricsDir", func(t *testing.T) {
		csvPath := ConductAnalysisAndUpload("test-prefix-", "2024", metricsDir, csvDir, nil, "")
		if !strings.HasPrefix(csvPath, csvDir) {
			t.Errorf("Expected csvPath to be in %s, got %s", csvDir, csvPath)
		}

		f, err := os.Open(csvPath)
		if err != nil {
			t.Fatalf("Failed to open generated CSV: %v", err)
		}
		defer f.Close()

		r := csv.NewReader(f)
		records, err := r.ReadAll()
		if err != nil {
			t.Fatalf("Failed to read CSV records: %v", err)
		}

		if len(records) != 3 { // Header + 2 entries
			t.Fatalf("Expected 3 records in CSV, got %d", len(records))
		}
		if records[0][0] != "CVEID" || records[0][1] != "Outcome" {
			t.Errorf("Unexpected header: %v", records[0])
		}

		outcomes := make(map[string]string)
		for _, rec := range records[1:] {
			outcomes[rec[0]] = rec[1]
		}

		if outcomes["CVE-2024-0001"] != models.Successful.String() {
			t.Errorf("Expected Successful for CVE-2024-0001, got %s", outcomes["CVE-2024-0001"])
		}
		if outcomes["CVE-2024-0002"] != models.NoCommitRanges.String() {
			t.Errorf("Expected NoCommitRanges for CVE-2024-0002, got %s", outcomes["CVE-2024-0002"])
		}
	})

	t.Run("Default csvDir to metricsDir when empty", func(t *testing.T) {
		csvPath := ConductAnalysisAndUpload("test-prefix-", "2024", metricsDir, "", nil, "")
		if !strings.HasPrefix(csvPath, metricsDir) {
			t.Errorf("Expected csvPath to be in %s, got %s", metricsDir, csvPath)
		}
		if _, err := os.Stat(csvPath); err != nil {
			t.Fatalf("Expected CSV file to exist at %s: %v", csvPath, err)
		}
	})

	t.Run("Upload to GCS with custom outcomes prefix", func(t *testing.T) {
		server, err := fakestorage.NewServerWithOptions(fakestorage.Options{
			Scheme: "http",
		})
		if err != nil {
			t.Fatalf("Failed to create fake storage server: %v", err)
		}
		defer server.Stop()

		t.Setenv("STORAGE_EMULATOR_HOST", server.URL())

		ctx := context.Background()
		bucketName := "test-outcomes-bucket"
		server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: bucketName})

		gcsHelper, err := gcs.InitUploadPool(ctx, 2, bucketName)
		if err != nil {
			t.Fatalf("Failed to init upload pool: %v", err)
		}

		outcomesPrefix := "metadata/cve5/outcomes"
		csvPath := ConductAnalysisAndUpload("test-prefix-", "2024", metricsDir, csvDir, gcsHelper, outcomesPrefix)
		gcsHelper.CloseAndWait()

		client := server.Client()
		bkt := client.Bucket(bucketName)
		objName := path.Join(outcomesPrefix, filepath.Base(csvPath))
		_, err = bkt.Object(objName).Attrs(ctx)
		if err != nil {
			t.Fatalf("Expected outcomes CSV %q to exist on GCS, got error: %v", objName, err)
		}
	})
}

func TestGitVersionsToCommits_Canonicalization(t *testing.T) {
	tests := []struct {
		name           string
		versionRanges  []models.RangeWithMetadata
		repos          []string
		canonicalLinks map[string]string
		cachedTags     map[string]git.RepoTagsMap
		wantResolved   int
		wantUnresolved int
		wantSuccessful []string
	}{
		{
			name: "Range repo is alias, Loop repo is canonical",
			versionRanges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "http://github.com/alias/repo",
						Events: []*osvschema.Event{
							{Introduced: "1.0.0"},
							{Fixed: "1.0.1"},
						},
					},
				},
			},
			repos: []string{"https://github.com/canonical/repo"},
			canonicalLinks: map[string]string{
				"http://github.com/alias/repo":      "https://github.com/canonical/repo",
				"https://github.com/canonical/repo": "https://github.com/canonical/repo",
			},
			cachedTags: map[string]git.RepoTagsMap{
				"https://github.com/canonical/repo": {
					NormalizedTag: map[string]git.NormalizedTag{
						"1-0-0": {OriginalTag: "v1.0.0", Commit: "100commit"},
						"1-0-1": {OriginalTag: "v1.0.1", Commit: "101commit"},
					},
				},
			},
			wantResolved:   1,
			wantUnresolved: 0,
			wantSuccessful: []string{"https://github.com/canonical/repo"},
		},
		{
			name: "Range repo is canonical, Loop repo is alias",
			versionRanges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "https://github.com/canonical/repo",
						Events: []*osvschema.Event{
							{Introduced: "1.0.0"},
							{Fixed: "1.0.1"},
						},
					},
				},
			},
			repos: []string{"http://github.com/alias/repo"},
			canonicalLinks: map[string]string{
				"http://github.com/alias/repo":      "https://github.com/canonical/repo",
				"https://github.com/canonical/repo": "https://github.com/canonical/repo",
			},
			cachedTags: map[string]git.RepoTagsMap{
				"https://github.com/canonical/repo": {
					NormalizedTag: map[string]git.NormalizedTag{
						"1-0-0": {OriginalTag: "v1.0.0", Commit: "100commit"},
						"1-0-1": {OriginalTag: "v1.0.1", Commit: "101commit"},
					},
				},
			},
			wantResolved:   1,
			wantUnresolved: 0,
			wantSuccessful: []string{"https://github.com/canonical/repo"},
		},
		{
			name: "Range without repo, Loop repo is alias",
			versionRanges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1.0.0"},
							{Fixed: "1.0.1"},
						},
					},
				},
			},
			repos: []string{"http://github.com/alias/repo"},
			canonicalLinks: map[string]string{
				"http://github.com/alias/repo":      "https://github.com/canonical/repo",
				"https://github.com/canonical/repo": "https://github.com/canonical/repo",
			},
			cachedTags: map[string]git.RepoTagsMap{
				"https://github.com/canonical/repo": {
					NormalizedTag: map[string]git.NormalizedTag{
						"1-0-0": {OriginalTag: "v1.0.0", Commit: "100commit"},
						"1-0-1": {OriginalTag: "v1.0.1", Commit: "101commit"},
					},
				},
			},
			wantResolved:   1,
			wantUnresolved: 0,
			wantSuccessful: []string{"https://github.com/canonical/repo"},
		},
		{
			name: "Range without repo skipped if repo claimed by another range",
			versionRanges: []models.RangeWithMetadata{
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT,
						Repo: "http://github.com/alias/repo", // Claims the repo
						Events: []*osvschema.Event{
							{Introduced: "1.0.0"},
							{Fixed: "1.0.1"},
						},
					},
				},
				{
					Range: &osvschema.Range{
						Type: osvschema.Range_GIT, // No repo
						Events: []*osvschema.Event{
							{Introduced: "2.0.0"},
							{Fixed: "2.0.1"},
						},
					},
				},
			},
			repos: []string{"https://github.com/canonical/repo"},
			canonicalLinks: map[string]string{
				"http://github.com/alias/repo":      "https://github.com/canonical/repo",
				"https://github.com/canonical/repo": "https://github.com/canonical/repo",
			},
			cachedTags: map[string]git.RepoTagsMap{
				"https://github.com/canonical/repo": {
					NormalizedTag: map[string]git.NormalizedTag{
						"1-0-0": {OriginalTag: "v1.0.0", Commit: "100commit"},
						"1-0-1": {OriginalTag: "v1.0.1", Commit: "101commit"},
						"2-0-0": {OriginalTag: "v2.0.0", Commit: "200commit"},
						"2-0-1": {OriginalTag: "v2.0.1", Commit: "201commit"},
					},
				},
			},
			wantResolved:   1, // Only the first range should be resolved by this repo
			wantUnresolved: 1, // The second range should remain unresolved
			wantSuccessful: []string{"https://github.com/canonical/repo"},
		},
	}

	for _, tt := range tests {
		oldRedisHost := os.Getenv("REDISHOST")
		os.Unsetenv("REDISHOST")
		defer func() {
			if oldRedisHost != "" {
				t.Setenv("REDISHOST", oldRedisHost)
			}
		}()

		cache := git.NewRepoTagsCache()
		for k, v := range tt.canonicalLinks {
			cache.SetCanonicalLink(k, v)
		}
		for k, v := range tt.cachedTags {
			cache.Set(k, v)
		}
		httpClient := http.DefaultClient
		t.Run(tt.name, func(t *testing.T) {
			metrics := &models.ConversionMetrics{}
			gotResolved, gotUnresolved, gotSuccessful := GitVersionsToCommits(tt.versionRanges, tt.repos, metrics, cache, httpClient)

			if len(gotResolved) != tt.wantResolved {
				t.Errorf("GitVersionsToCommits() gotResolved count = %v, want %v", len(gotResolved), tt.wantResolved)
			}
			if len(gotUnresolved) != tt.wantUnresolved {
				t.Errorf("GitVersionsToCommits() gotUnresolved count = %v, want %v", len(gotUnresolved), tt.wantUnresolved)
			}
			if diff := cmp.Diff(tt.wantSuccessful, gotSuccessful); diff != "" {
				t.Errorf("GitVersionsToCommits() gotSuccessful mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
