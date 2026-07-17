// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

type echoTestCase struct {
	v1  string
	v2  string
	cmp int
}

func runEchoTest(t *testing.T, e Ecosystem, tests []echoTestCase) {
	t.Helper()

	for _, tc := range tests {
		v1, err := e.Parse(tc.v1)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", tc.v1, err)
		}
		v2, err := e.Parse(tc.v2)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", tc.v2, err)
		}

		c, err := v1.Compare(v2)
		if err != nil {
			t.Fatalf("Compare(%q, %q) error: %v", tc.v1, tc.v2, err)
		}

		if c != tc.cmp {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.v1, tc.v2, c, tc.cmp)
		}
	}
}

// SemVer excludes build metadata from precedence, so Echo:npm must tie-break
// on the +echo.N build number. This is the "smart" comparison that Maven/PyPI
// don't need (they order +echo.N natively).
func TestEchoEcosystem_NPM(t *testing.T) {
	e := echoFactory(nil, "npm")
	tests := []echoTestCase{
		// Base SemVer ordering (unchanged), including prereleases.
		{"1.0.1", "1.0.0", 1},
		{"1.10.0", "1.9.0", 1},
		{"1.0.0", "1.0.0-rc.0", 1},
		{"1.0.0-beta.42", "1.0.0-alpha.1", 1},
		// +echo.N ordering: base < echo.1 < echo.2 < echo.10 < next patch.
		{"2.14.2+echo.1", "2.14.2", 1},
		{"2.14.2+echo.2", "2.14.2+echo.1", 1},
		{"2.14.2+echo.10", "2.14.2+echo.2", 1},
		{"2.14.3", "2.14.2+echo.1", 1},
		{"2.14.2+echo.1", "2.14.2+echo.1", 0},
		// A +echo.N build of a prerelease still sorts before the final release.
		{"19.0.0-next.3+echo.1", "19.0.0-next.3", 1},
		{"19.0.0", "19.0.0-next.3+echo.1", 1},
	}
	runEchoTest(t, e, tests)
}

func TestEchoEcosystem_Maven(t *testing.T) {
	e := echoFactory(nil, "maven")
	tests := []echoTestCase{
		{"3.1.1+echo.1", "3.1.1", 1},
		{"3.1.1+echo.2", "3.1.1+echo.1", 1},
		{"3.1.2", "3.1.1+echo.1", 1},
	}
	runEchoTest(t, e, tests)
}

func TestEchoEcosystem_PyPI(t *testing.T) {
	e := echoFactory(nil, "pypi")
	tests := []echoTestCase{
		{"2.14.2+echo.1", "2.14.2", 1},
		{"2.14.2+echo.2", "2.14.2+echo.1", 1},
		{"2.14.3", "2.14.2+echo.1", 1},
	}
	runEchoTest(t, e, tests)
}
