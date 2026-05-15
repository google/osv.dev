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

func TestTuxCareEcosystem_DelegatesToInner(t *testing.T) {
	p := NewProvider(nil)

	cases := []struct {
		name      string
		ecosystem string
	}{
		{"RedHat", "TuxCare:Red Hat"},
		{"AlmaLinux", "TuxCare:AlmaLinux"},
		{"Debian", "TuxCare:Debian:12"},
		{"NPM", "TuxCare:npm"},
		{"AlpineWithSuffix", "TuxCare:Alpine:v3.16"},
		{"UbuntuMultiSegment", "TuxCare:Ubuntu:22.04:LTS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := p.Get(tc.ecosystem); !ok {
				t.Fatalf("Provider.Get(%q) = ok=false, want true", tc.ecosystem)
			}
		})
	}
}

func TestTuxCareEcosystem_Malformed(t *testing.T) {
	p := NewProvider(nil)
	cases := []string{
		// Bare TuxCare with no suffix.
		"TuxCare",
		"TuxCare:",
		// Nested TuxCare.
		"TuxCare:TuxCare",
		"TuxCare:TuxCare:Red Hat",
	}
	for _, ecosystem := range cases {
		t.Run(ecosystem, func(t *testing.T) {
			if e, ok := p.Get(ecosystem); ok {
				t.Errorf("Provider.Get(%q) = (%v, true), want (_, false)", ecosystem, e)
			}
		})
	}
}

// Unknown inner ecosystems are accepted by Get (the inner is resolved
// lazily, mirroring debianFactory which accepts any release suffix); the
// failure surfaces at Parse time.
func TestTuxCareEcosystem_UnknownInnerFailsAtParse(t *testing.T) {
	p := NewProvider(nil)
	e, ok := p.Get("TuxCare:NotARealEcosystem")
	if !ok {
		t.Fatalf("Provider.Get(TuxCare:NotARealEcosystem) = ok=false, want true")
	}
	if _, err := e.Parse("1.0.0"); err == nil {
		t.Errorf("Parse on unknown inner ecosystem returned nil error, want non-nil")
	}
}

func TestTuxCareEcosystem_SortMatchesInner(t *testing.T) {
	p := NewProvider(nil)

	tuxRPM, ok := p.Get("TuxCare:Red Hat")
	if !ok {
		t.Fatalf("TuxCare:Red Hat not found")
	}
	plainRPM, ok := p.Get("Red Hat")
	if !ok {
		t.Fatalf("Red Hat not found")
	}

	v1, err := tuxRPM.Parse("1.0.0-1")
	if err != nil {
		t.Fatalf("tuxRPM.Parse: %v", err)
	}
	v2, err := tuxRPM.Parse("1.0.1-1")
	if err != nil {
		t.Fatalf("tuxRPM.Parse: %v", err)
	}
	if c, err := v1.Compare(v2); err != nil || c != -1 {
		t.Errorf("Compare(1.0.0-1, 1.0.1-1) = (%d, %v), want (-1, nil)", c, err)
	}

	// Sort behaviour matches the underlying RPM parser.
	tv, err := tuxRPM.Parse("1.2.3-1.el8")
	if err != nil {
		t.Fatalf("tuxRPM.Parse: %v", err)
	}
	pv, err := plainRPM.Parse("1.2.3-1.el8")
	if err != nil {
		t.Fatalf("plainRPM.Parse: %v", err)
	}
	if c, err := tv.Compare(pv); err != nil || c != 0 {
		t.Errorf("Compare(tuxRPM, plainRPM) = (%d, %v), want (0, nil)", c, err)
	}
}

func TestTuxCareEcosystem_ZeroVersion(t *testing.T) {
	p := NewProvider(nil)
	e, ok := p.Get("TuxCare:Red Hat")
	if !ok {
		t.Fatalf("TuxCare:Red Hat not found")
	}
	zero, err := e.Parse("0")
	if err != nil {
		t.Fatalf("Parse(0): %v", err)
	}
	v, err := e.Parse("1.0.0-1")
	if err != nil {
		t.Fatalf("Parse(1.0.0-1): %v", err)
	}
	if c, err := zero.Compare(v); err != nil || c != -1 {
		t.Errorf("Compare(0, 1.0.0-1) = (%d, %v), want (-1, nil)", c, err)
	}
}
