package purl

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		ecosystem   string
		packageName string
		want        string
		wantErr     bool
	}{
		{"PyPI", "requests", "pkg:pypi/requests", false},
		{"crates.io", "rand", "pkg:cargo/rand", false},
		{"Debian", "curl", "pkg:deb/debian/curl?arch=source", false},
		{"Debian:11", "curl", "pkg:deb/debian/curl?arch=source&distro=bullseye", false},
		{"Debian:12", "curl", "pkg:deb/debian/curl?arch=source&distro=bookworm", false},
		{"Debian:99", "curl", "pkg:deb/debian/curl?arch=source&distro=99", false}, // fallback
		{"Alpine:v2.23", "curl", "pkg:apk/alpine/curl?arch=source", false},
		{"Go", "github.com/gorilla/mux", "pkg:golang/github.com/gorilla/mux", false},
		{"Go", "stdlib", "pkg:golang/stdlib", false},
		{"Maven", "org.apache.commons:commons-lang3", "pkg:maven/org.apache.commons/commons-lang3", false},
		// Error cases
		{"UnknownEcosystem", "package", "", true},
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

func TestParse(t *testing.T) {
	tests := []struct {
		purlStr       string
		wantEcosystem string
		wantPackage   string
		wantVersion   string
		wantErr       bool
	}{
		{"pkg:pypi/requests@2.28.1", "PyPI", "requests", "2.28.1", false},
		{"pkg:cargo/rand@0.8.5", "crates.io", "rand", "0.8.5", false},
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source", "Debian", "curl", "7.74.0-1.3+deb11u1", false},
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source&distro=bullseye", "Debian:11", "curl", "7.74.0-1.3+deb11u1", false},
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source&distro=11", "Debian:11", "curl", "7.74.0-1.3+deb11u1", false},       // lenient
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source&distro=Bullseye", "Debian:11", "curl", "7.74.0-1.3+deb11u1", false}, // case-insensitive
		{"pkg:golang/github.com/gorilla/mux@v1.8.0", "Go", "github.com/gorilla/mux", "v1.8.0", false},
		{"pkg:golang/stdlib@1.18", "Go", "stdlib", "1.18", false},
		{"pkg:maven/org.apache.commons/commons-lang3@3.12.0", "Maven", "org.apache.commons:commons-lang3", "3.12.0", false},
		{"pkg:gradle/org.apache.commons/commons-lang3@3.12.0", "Maven", "org.apache.commons:commons-lang3", "3.12.0", false}, // alias
		// Error cases
		{"invalid-purl", "", "", "", true},
		{"pkg:unknown/package@1.0.0", "", "", "", true},
	}

	for _, tt := range tests {
		eco, pkg, ver, err := Parse(tt.purlStr)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q) error = %v, wantErr %v", tt.purlStr, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if eco != tt.wantEcosystem || pkg != tt.wantPackage || ver != tt.wantVersion {
			t.Errorf("Parse(%q) = (%q, %q, %q), want (%q, %q, %q)", tt.purlStr, eco, pkg, ver, tt.wantEcosystem, tt.wantPackage, tt.wantVersion)
		}
	}
}
