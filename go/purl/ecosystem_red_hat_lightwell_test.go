package purl

import (
	"testing"
)

func TestRedHatLightwellGenerate(t *testing.T) {
	tests := []struct {
		ecosystem   string
		packageName string
		want        string
		wantErr     bool
	}{
		{"Red Hat Lightwell:Maven", "org.apache.commons:commons-lang3", "pkg:maven/org.apache.commons/commons-lang3", false},
		{"Red Hat Lightwell:PyPI", "requests", "pkg:pypi/requests", false},
		// Unsupported / missing suffix.
		{"Red Hat Lightwell:npm", "foo", "", true},
		{"Red Hat Lightwell", "foo", "", true},
	}

	for _, tt := range tests {
		got, err := Generate(tt.ecosystem, tt.packageName)
		if (err != nil) != tt.wantErr {
			t.Errorf("Generate(%q, %q) error = %v, wantErr %v", tt.ecosystem, tt.packageName, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if got != tt.want {
			t.Errorf("Generate(%q, %q) = %q, want %q", tt.ecosystem, tt.packageName, got, tt.want)
		}
	}
}
