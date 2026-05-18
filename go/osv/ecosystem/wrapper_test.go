package ecosystem

import (
	"testing"
)

func TestZeroVersion(t *testing.T) {
	// Test that 0 is less than any other version
	tests := []struct {
		ecosystem string
		version   string
	}{
		// Generic case
		{"PyPI", "1.2.3"},
		// Ecosystems where the version "0" is technically greater than other versions
		// We need to specifically force "0" to be less than other versions (per the schema).
		{"Maven", "alpha-alpha-alpha"},
		{"npm", "0-pre"},
		{"AlmaLinux:8", "B.02.19.2-6.el8"},                                                 // ALBA-2021:4442
		{"Azure Linux:2", "5.15.55.1-1"},                                                   // AZL-10003
		{"Debian:11", "0~20200923.3-2+deb11u1"},                                            // DLA-4116-1
		{"Go", "0.0.0-20250619215741-6356e984b82a"},                                        // GHSA-24ch-w38v-xmh8
		{"Mageia:9", "gtk+2.0-2.24.33-5.1.mga9"},                                           // MGASA-2024-0312
		{"openEuler:24.03-LTS", "java-1.8.0-openjdk-1.8.0.462.b08-4.oe2403sp2"},            // OESA-2025-2072
		{"PyPI", "2019-09-12"},                                                             // PYSEC-2019-125
		{"Red Hat:service_mesh:1.1::el7", "0:v1.12.10.redhat2-1.el7"},                      // RHSA-2020:3369
		{"SUSE:Linux Enterprise Server LTSS Extended Security 12 SP5", "s20161105-11.9.1"}, // SUSE-SU-2025:01777-1
		{"Ubuntu:22.04:LTS", "0~20210324.2-2ubuntu0.2"},                                    // UBUNTU-CVE-2025-0838
		{"openSUSE:Tumbleweed", "0~20240902.c95cc9e-1.1"},                                  // openSUSE-SU-2024:14314-1
	}

	p := NewProvider(nil)
	for _, test := range tests {
		e, ok := p.Get(test.ecosystem)
		if !ok {
			t.Fatalf("%s ecosystem not found", test.ecosystem)
		}

		v, err := e.Parse("0")
		if err != nil {
			t.Fatalf("failed to parse '0': %v", err)
		}

		v1, err := e.Parse(test.version)
		if err != nil {
			t.Fatalf("failed to parse '%s': %v", test.version, err)
		}

		if c, err := v.Compare(v1); err != nil {
			t.Errorf("comparison error: %v", err)
		} else if c >= 0 {
			t.Errorf("expected 0 < %s, got compare result %d", test.version, c)
		}
	}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		ecosystem string
		name      string
		expected  string
	}{
		{"PyPI", "Flask", "flask"},
		{"PyPI", "flask", "flask"},
		{"PyPI", "A_B-C.D", "a-b-c-d"},
		{"PyPI", "A_._B", "a-b"},
		{"npm", "Flask", "Flask"}, // No normalization
	}

	p := NewProvider(nil)
	for _, test := range tests {
		e, ok := p.Get(test.ecosystem)
		if !ok {
			t.Fatalf("%s ecosystem not found", test.ecosystem)
		}

		actual := NormalizePackageName(e, test.name)
		if actual != test.expected {
			t.Errorf("NormalizePackageName(%s, %q) = %q, expected %q", test.ecosystem, test.name, actual, test.expected)
		}
	}
}
