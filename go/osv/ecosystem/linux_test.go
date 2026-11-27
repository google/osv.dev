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

func TestLinuxEcosystem_Compare(t *testing.T) {
	t.Parallel()
	e, ok := DefaultProvider.Get("Linux")
	if !ok {
		t.Fatal("Linux ecosystem not found")
	}
	if e.IsSemver() {
		t.Error("Linux.IsSemver() = true, want false")
	}

	orderedGroups := [][]string{
		{"0"},
		{"2.6.12-rc2", "v2.6.12-rc2"},
		{"2.6.12", "2.6.12.0", "v2.6.12"},
		{"2.6.39"},
		{"2.6.39.1"},
		{"2.6.39.2", "v2.6.39.2"},
		{"2.6.39.10"},
		{"3.0-rc1"},
		{"3.0", "3.0.0", "v3.0"},
		{"3.1-rc2"},
		{"3.1-rc10"},
		{"3.1"},
		{"5.12-rc1", "v5.12-rc1", "5.12.0-rc01"},
		{"v5.12-rc1-dontuse"},
		{"5.12-rc2", "v5.12-rc2"},
		{"5.12", "5.12.0", "v5.12"},
		{"5.16.0"},
		{"6.1", "6.1.0", "v6.1", "v6.1.0"},
		{"6.1.100", "v6.1.100"},
		{"6.1.120"},
		{"6.2.0", "6.2"},
	}

	for i, groupA := range orderedGroups {
		for _, aStr := range groupA {
			va, err := e.Parse(aStr)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", aStr, err)
			}
			// Every version within the same equivalence group must compare equal.
			for _, sameStr := range groupA {
				vs, err := e.Parse(sameStr)
				if err != nil {
					t.Fatalf("Parse(%q) unexpected error: %v", sameStr, err)
				}
				if c, err := va.Compare(vs); err != nil || c != 0 {
					t.Errorf("Compare(%q, %q) = (%d, %v), want (0, nil)", aStr, sameStr, c, err)
				}
				checkCoarseMonotonicityRaw(t, e, aStr, sameStr)
			}
			// Every version in an earlier group must compare strictly less than later groups.
			for _, groupB := range orderedGroups[i+1:] {
				for _, bStr := range groupB {
					vb, err := e.Parse(bStr)
					if err != nil {
						t.Fatalf("Parse(%q) unexpected error: %v", bStr, err)
					}
					if c, err := va.Compare(vb); err != nil || c >= 0 {
						t.Errorf("Compare(%q, %q) = (%d, %v), want (<0, nil)", aStr, bStr, c, err)
					}
					if c, err := vb.Compare(va); err != nil || c <= 0 {
						t.Errorf("Compare(%q, %q) = (%d, %v), want (>0, nil)", bStr, aStr, c, err)
					}
					checkCoarseMonotonicityRaw(t, e, aStr, bStr)
				}
			}
		}
	}
}

func TestLinuxEcosystem_Coarse(t *testing.T) {
	t.Parallel()
	e, ok := DefaultProvider.Get("Linux")
	if !ok {
		t.Fatal("Linux ecosystem not found")
	}

	tests := []struct {
		version string
		want    string
	}{
		{"0", "00:00000000.00000000.00000000"},
		{"6.1", "00:00000006.00000001.00000000"},
		{"6.1.0", "00:00000006.00000001.00000000"},
		{"v6.1-rc1", "00:00000006.00000001.00000000"},
		{"6.1.100", "00:00000006.00000001.00000100"},
		{"v6.1.100", "00:00000006.00000001.00000100"},
		{"2.6.39.2", "00:00000002.00000006.00000039"},
		{"v5.12-rc1-dontuse", "00:00000005.00000012.00000000"},
	}

	for _, tc := range tests {
		got, err := e.Coarse(tc.version)
		if err != nil {
			t.Errorf("Coarse(%q) unexpected error: %v", tc.version, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Coarse(%q) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestLinuxEcosystem_InvalidVersions(t *testing.T) {
	t.Parallel()
	e, ok := DefaultProvider.Get("Linux")
	if !ok {
		t.Fatal("Linux ecosystem not found")
	}

	invalid := []string{
		"",
		"v",
		"6..1",
		".6.1",
		"6.1.",
		"6.1-rc",
		"5.15.0-105-generic",
		"6.1.0-25-amd64",
		"6.1.100+build1",
		"not-a-version",
	}

	for _, v := range invalid {
		if _, err := e.Parse(v); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", v)
		}
		if _, err := e.Coarse(v); err == nil {
			t.Errorf("Coarse(%q) succeeded, want error", v)
		}
	}
}
