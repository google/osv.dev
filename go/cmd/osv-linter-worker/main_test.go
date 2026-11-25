package main

import (
	"testing"
)

func TestResolveConfig(t *testing.T) {
	tests := []struct {
		name                 string
		env                  map[string]string
		projectOverride      string
		datastoreDBOverride  string
		vulnBucketOverride   string
		linterBucketOverride string
		want                 workerConfig
	}{
		{
			name: "defaults when unset",
			want: workerConfig{
				gcpProject:         "oss-vdb-test",
				datastoreDB:        "",
				vulnBucket:         "osv-test-vulnerabilities",
				linterExportBucket: "osv-test-public-import-logs",
			},
		},
		{
			name: "environment variables override defaults",
			env: map[string]string{
				"GOOGLE_CLOUD_PROJECT":       "oss-vdb",
				"DATASTORE_DATABASE_ID":      "custom-db",
				"OSV_VULNERABILITIES_BUCKET": "osv-vulnerabilities",
				"OSV_LINTER_BUCKET":          "osv-public-import-logs",
			},
			want: workerConfig{
				gcpProject:         "oss-vdb",
				datastoreDB:        "custom-db",
				vulnBucket:         "osv-vulnerabilities",
				linterExportBucket: "osv-public-import-logs",
			},
		},
		{
			name: "legacy GCP_PROJECT fallback when GOOGLE_CLOUD_PROJECT unset",
			env: map[string]string{
				"GCP_PROJECT": "legacy-project",
			},
			want: workerConfig{
				gcpProject:         "legacy-project",
				datastoreDB:        "",
				vulnBucket:         "osv-test-vulnerabilities",
				linterExportBucket: "osv-test-public-import-logs",
			},
		},
		{
			name: "GOOGLE_CLOUD_PROJECT takes precedence over GCP_PROJECT",
			env: map[string]string{
				"GOOGLE_CLOUD_PROJECT": "primary-project",
				"GCP_PROJECT":          "legacy-project",
			},
			want: workerConfig{
				gcpProject:         "primary-project",
				datastoreDB:        "",
				vulnBucket:         "osv-test-vulnerabilities",
				linterExportBucket: "osv-test-public-import-logs",
			},
		},
		{
			name: "flags override environment variables",
			env: map[string]string{
				"GOOGLE_CLOUD_PROJECT":       "env-project",
				"DATASTORE_DATABASE_ID":      "env-db",
				"OSV_VULNERABILITIES_BUCKET": "env-vuln-bucket",
				"OSV_LINTER_BUCKET":          "env-linter-bucket",
			},
			projectOverride:      "flag-project",
			datastoreDBOverride:  "flag-db",
			vulnBucketOverride:   "flag-vuln-bucket",
			linterBucketOverride: "flag-linter-bucket",
			want: workerConfig{
				gcpProject:         "flag-project",
				datastoreDB:        "flag-db",
				vulnBucket:         "flag-vuln-bucket",
				linterExportBucket: "flag-linter-bucket",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOOGLE_CLOUD_PROJECT", "")
			t.Setenv("GCP_PROJECT", "")
			t.Setenv("DATASTORE_DATABASE_ID", "")
			t.Setenv("OSV_VULNERABILITIES_BUCKET", "")
			t.Setenv("OSV_LINTER_BUCKET", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			got := resolveConfig(tc.projectOverride, tc.datastoreDBOverride, tc.vulnBucketOverride, tc.linterBucketOverride)
			if got != tc.want {
				t.Errorf("resolveConfig() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
