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

package models

import "testing"

func TestNormalizeUbuntuEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"Ubuntu:22.04", "Ubuntu:22.04"},
		{"Ubuntu:22.04:LTS", "Ubuntu:22.04"},
		{"Ubuntu:Pro:22.04:LTS", "Ubuntu:22.04"},
		{"Ubuntu:Pro:FIPS-updates:22.04:LTS", "Ubuntu:FIPS-updates:22.04"},
		{"Ubuntu:25.04", "Ubuntu:25.04"},
		{"Ubuntu", "Ubuntu"},
		{"Debian:12", "Debian:12"},
	}

	for _, tc := range tests {
		if got := NormalizeUbuntuEcosystem(tc.input); got != tc.want {
			t.Errorf("NormalizeUbuntuEcosystem(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestIsValidUbuntuReleaseEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"Ubuntu:22.04", true},
		{"Ubuntu:22.04:LTS", true},
		{"Ubuntu:Pro:18.04:LTS", true},
		{"Ubuntu:Pro:FIPS-updates:22.04:LTS", true},
		{"Ubuntu:Nvidia-BlueField:22.04:LTS", true},
		{"Ubuntu:25.04", true},
		{"", false},
		{"Ubuntu", false},
		{"Ubuntu:", false},
		{"Ubuntu:LTS", false},
		{"Ubuntu:Pro", false},
		{"Ubuntu:Pro:LTS", false},
		{"Ubuntu::22.04", false},
		{"Ubuntu:22.04:", false},
		{"Ubuntu: 22.04", false},
		{"Ubuntu:   ", false},
		{"Debian:12", false},
	}

	for _, tc := range tests {
		if got := IsValidUbuntuReleaseEcosystem(tc.input); got != tc.want {
			t.Errorf("IsValidUbuntuReleaseEcosystem(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
