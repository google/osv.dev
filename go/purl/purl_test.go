package purl

import (
	"testing"
)

func TestPackageToPURL(t *testing.T) {
	tests := []struct {
		ecosystem   string
		packageName string
		want        string
	}{
		{"PyPI", "requests", "pkg:pypi/requests"},
		{"crates.io", "rand", "pkg:cargo/rand"},
		{"Debian", "curl", "pkg:deb/debian/curl?arch=source"},
		{"Debian:11", "curl", "pkg:deb/debian/curl?arch=source&distro=bullseye"},
		{"Debian:12", "curl", "pkg:deb/debian/curl?arch=source&distro=bookworm"},
		{"Debian:99", "curl", "pkg:deb/debian/curl?arch=source&distro=99"}, // fallback
		{"Alpine:v2.23", "curl", "pkg:apk/alpine/curl?arch=source"},
		{"Go", "github.com/gorilla/mux", "pkg:golang/github.com/gorilla/mux"},
		{"Go", "stdlib", "pkg:golang/stdlib"},
		{"Maven", "org.apache.commons:commons-lang3", "pkg:maven/org.apache.commons/commons-lang3"},
	}

	for _, tt := range tests {
		got, err := PackageToPURL(tt.ecosystem, tt.packageName)
		if err != nil {
			t.Errorf("PackageToPURL(%q, %q) error: %v", tt.ecosystem, tt.packageName, err)
			continue
		}
		if got != tt.want {
			t.Errorf("PackageToPURL(%q, %q) = %q, want %q", tt.ecosystem, tt.packageName, got, tt.want)
		}
	}
}

func TestParsePURL(t *testing.T) {
	tests := []struct {
		purlStr       string
		wantEcosystem string
		wantPackage   string
		wantVersion   string
	}{
		{"pkg:pypi/requests@2.28.1", "PyPI", "requests", "2.28.1"},
		{"pkg:cargo/rand@0.8.5", "crates.io", "rand", "0.8.5"},
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source", "Debian", "curl", "7.74.0-1.3+deb11u1"},
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source&distro=bullseye", "Debian:11", "curl", "7.74.0-1.3+deb11u1"},
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source&distro=11", "Debian:11", "curl", "7.74.0-1.3+deb11u1"},       // lenient
		{"pkg:deb/debian/curl@7.74.0-1.3+deb11u1?arch=source&distro=Bullseye", "Debian:11", "curl", "7.74.0-1.3+deb11u1"}, // case-insensitive
		{"pkg:golang/github.com/gorilla/mux@v1.8.0", "Go", "github.com/gorilla/mux", "v1.8.0"},
		{"pkg:golang/stdlib@1.18", "Go", "stdlib", "1.18"},
		{"pkg:maven/org.apache.commons/commons-lang3@3.12.0", "Maven", "org.apache.commons:commons-lang3", "3.12.0"},
		{"pkg:gradle/org.apache.commons/commons-lang3@3.12.0", "Maven", "org.apache.commons:commons-lang3", "3.12.0"}, // alias
	}

	for _, tt := range tests {
		eco, pkg, ver, err := ParsePURL(tt.purlStr)
		if err != nil {
			t.Errorf("ParsePURL(%q) error: %v", tt.purlStr, err)
			continue
		}
		if eco != tt.wantEcosystem || pkg != tt.wantPackage || ver != tt.wantVersion {
			t.Errorf("ParsePURL(%q) = (%q, %q, %q), want (%q, %q, %q)", tt.purlStr, eco, pkg, ver, tt.wantEcosystem, tt.wantPackage, tt.wantVersion)
		}
	}
}
