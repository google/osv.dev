// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecosystem

import (
	"testing"
)

func TestDHIEcosystem_DelegatesToInner(t *testing.T) {
	p := NewProvider(nil)

	cases := []struct {
		name      string
		ecosystem string
	}{
		{"Alpine", "Docker Hardened Images:Alpine:3.23"},
		{"Debian", "Docker Hardened Images:Debian:trixie"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := p.Get(tc.ecosystem); !ok {
				t.Fatalf("Provider.Get(%q) = ok=false, want true", tc.ecosystem)
			}
		})
	}
}

func TestDHIEcosystem_Malformed(t *testing.T) {
	p := NewProvider(nil)
	cases := []string{
		// Bare "Docker Hardened Images" with no lineage suffix.
		"Docker Hardened Images",
		"Docker Hardened Images:",
		// Self-referential suffix.
		"Docker Hardened Images:Docker Hardened Images",
	}
	for _, ecosystem := range cases {
		t.Run(ecosystem, func(t *testing.T) {
			if e, ok := p.Get(ecosystem); ok {
				t.Errorf("Provider.Get(%q) = (%v, true), want (_, false)", ecosystem, e)
			}
		})
	}
}

// IsSemver is false: DHI uses ECOSYSTEM ranges, not SEMVER.
func TestDHIEcosystem_IsSemverFalse(t *testing.T) {
	p := NewProvider(nil)
	e, ok := p.Get("Docker Hardened Images:Alpine:3.23")
	if !ok {
		t.Fatalf("Docker Hardened Images:Alpine:3.23 not found")
	}
	if e.IsSemver() {
		t.Errorf("IsSemver() = true, want false")
	}
}

// The Alpine lineage sorts with apk semantics, not SemVer. In particular the
// "-rN" package release is ordered numerically (r2 < r10); a SemVer comparison
// would invert this by comparing the prerelease identifiers "r10" and "r2"
// lexically. Results also match the plain Alpine parser.
func TestDHIEcosystem_AlpineLineage(t *testing.T) {
	p := NewProvider(nil)

	dhi, ok := p.Get("Docker Hardened Images:Alpine:3.23")
	if !ok {
		t.Fatalf("Docker Hardened Images:Alpine:3.23 not found")
	}
	alpine, ok := p.Get("Alpine:3.23")
	if !ok {
		t.Fatalf("Alpine:3.23 not found")
	}

	v1, err := dhi.Parse("8.4.0-r0")
	if err != nil {
		t.Fatalf("dhi.Parse(8.4.0-r0): %v", err)
	}
	v2, err := dhi.Parse("8.5.0-r0")
	if err != nil {
		t.Fatalf("dhi.Parse(8.5.0-r0): %v", err)
	}
	if c, err := v1.Compare(v2); err != nil || c != -1 {
		t.Errorf("Compare(8.4.0-r0, 8.5.0-r0) = (%d, %v), want (-1, nil)", c, err)
	}

	// apk orders the -rN release numerically, unlike SemVer prerelease ordering.
	r2, err := dhi.Parse("1.2.3-r2")
	if err != nil {
		t.Fatalf("dhi.Parse(1.2.3-r2): %v", err)
	}
	r10, err := dhi.Parse("1.2.3-r10")
	if err != nil {
		t.Fatalf("dhi.Parse(1.2.3-r10): %v", err)
	}
	if c, err := r2.Compare(r10); err != nil || c != -1 {
		t.Errorf("Compare(1.2.3-r2, 1.2.3-r10) = (%d, %v), want (-1, nil)", c, err)
	}

	// Delegation matches the plain Alpine parser.
	dv, err := dhi.Parse("8.4.0-r0")
	if err != nil {
		t.Fatalf("dhi.Parse: %v", err)
	}
	av, err := alpine.Parse("8.4.0-r0")
	if err != nil {
		t.Fatalf("alpine.Parse: %v", err)
	}
	if c, err := dv.Compare(av); err != nil || c != 0 {
		t.Errorf("Compare(dhi, alpine) = (%d, %v), want (0, nil)", c, err)
	}
}

// The Debian lineage sorts with dpkg semantics (epoch/revision aware) and
// matches the plain Debian parser.
func TestDHIEcosystem_DebianLineage(t *testing.T) {
	p := NewProvider(nil)

	dhi, ok := p.Get("Docker Hardened Images:Debian:trixie")
	if !ok {
		t.Fatalf("Docker Hardened Images:Debian:trixie not found")
	}
	debian, ok := p.Get("Debian:trixie")
	if !ok {
		t.Fatalf("Debian:trixie not found")
	}

	v1, err := dhi.Parse("7.88.1-10+deb13u1")
	if err != nil {
		t.Fatalf("dhi.Parse(7.88.1-10+deb13u1): %v", err)
	}
	v2, err := dhi.Parse("7.88.1-10+deb13u2")
	if err != nil {
		t.Fatalf("dhi.Parse(7.88.1-10+deb13u2): %v", err)
	}
	if c, err := v1.Compare(v2); err != nil || c != -1 {
		t.Errorf("Compare(deb13u1, deb13u2) = (%d, %v), want (-1, nil)", c, err)
	}

	dv, err := dhi.Parse("7.88.1-10+deb13u2")
	if err != nil {
		t.Fatalf("dhi.Parse: %v", err)
	}
	bv, err := debian.Parse("7.88.1-10+deb13u2")
	if err != nil {
		t.Fatalf("debian.Parse: %v", err)
	}
	if c, err := dv.Compare(bv); err != nil || c != 0 {
		t.Errorf("Compare(dhi, debian) = (%d, %v), want (0, nil)", c, err)
	}
}

// An unknown lineage is accepted by Get (resolved lazily, mirroring TuxCare);
// the failure surfaces at Parse time.
func TestDHIEcosystem_UnknownLineageFailsAtParse(t *testing.T) {
	p := NewProvider(nil)
	e, ok := p.Get("Docker Hardened Images:NotARealEcosystem")
	if !ok {
		t.Fatalf("Provider.Get(Docker Hardened Images:NotARealEcosystem) = ok=false, want true")
	}
	if _, err := e.Parse("1.0.0"); err == nil {
		t.Errorf("Parse on unknown lineage returned nil error, want non-nil")
	}
}
