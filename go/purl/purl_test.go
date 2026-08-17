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
		{"Packagist", "drupal/colorbox", "pkg:composer/drupal/colorbox", false},
		{"npm", "@babel/core", "pkg:npm/%40babel/core", false},
		{"Hex", "acme/foo", "pkg:hex/acme/foo", false},
		{"SwiftURL", "github.com/apple/swift-markdown", "pkg:swift/github.com/apple/swift-markdown", false},
		{"Docker Hardened Images", "curl", "pkg:dhi/curl", false},
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
		{"pkg:composer/drupal/colorbox@1.2.3", "Packagist", "drupal/colorbox", "1.2.3", false},
		{"pkg:npm/%40babel/core@1.2.3", "npm", "@babel/core", "1.2.3", false},
		{"pkg:hex/acme/foo@1.2.3", "Hex", "acme/foo", "1.2.3", false},
		{"pkg:swift/github.com/apple/swift-markdown@1.2.3", "SwiftURL", "github.com/apple/swift-markdown", "1.2.3", false},
		// Docker Hardened Images: release-lineage PURLs resolve to the ecosystem.
		// Qualifiers are ignored; versionless (OSV affected) and versioned (VEX
		// product) forms both parse. pkg:dhi/ also still resolves.
		{"pkg:apk/dhi/curl?os_distro=alpine&os_name=dhi&os_version=3.23", "Docker Hardened Images", "curl", "", false},
		{"pkg:apk/dhi/curl@8.4.0-r0", "Docker Hardened Images", "curl", "8.4.0-r0", false},
		{"pkg:deb/dhi/openssl@3.0.11-1", "Docker Hardened Images", "openssl", "3.0.11-1", false},
		{"pkg:dhi/curl@8.4.0-r0", "Docker Hardened Images", "curl", "8.4.0-r0", false},
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

func TestPackagistRepositoryRoundTrip(t *testing.T) {
	const (
		ecosystem   = "Packagist:https://packages.drupal.org/8"
		packageName = "drupal/commerce_guest_registration"
		wantPURL    = "pkg:composer/drupal/commerce_guest_registration?repository_url=https:%2F%2Fpackages.drupal.org%2F8"
	)

	gotPURL, err := Generate(ecosystem, packageName)
	if err != nil {
		t.Fatalf("Generate(%q, %q) returned an error: %v", ecosystem, packageName, err)
	}
	if gotPURL != wantPURL {
		t.Fatalf("Generate(%q, %q) = %q, want %q", ecosystem, packageName, gotPURL, wantPURL)
	}

	gotEcosystem, gotPackage, gotVersion, err := Parse(gotPURL)
	if err != nil {
		t.Fatalf("Parse(%q) returned an error: %v", gotPURL, err)
	}
	if gotEcosystem != ecosystem || gotPackage != packageName || gotVersion != "" {
		t.Errorf(
			"Parse(%q) = (%q, %q, %q), want (%q, %q, %q)",
			gotPURL,
			gotEcosystem,
			gotPackage,
			gotVersion,
			ecosystem,
			packageName,
			"",
		)
	}
}
