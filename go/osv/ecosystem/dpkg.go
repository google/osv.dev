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
	"fmt"
	"math/big"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// dpkgEcosystem is an ecosystem for ecosystems using Debian Package versioning.
type dpkgEcosystem struct{}

var _ Ecosystem = dpkgEcosystem{}

func (e dpkgEcosystem) Parse(version string) (Version, error) {
	ver, err := semantic.ParseDebianVersion(version)
	if err != nil {
		return nil, err
	}

	return SemanticVersionWrapper[semantic.DebianVersion]{ver}, nil
}

func (e dpkgEcosystem) Coarse(version string) (string, error) {
	version = strings.TrimSpace(version)
	epochStr, rest, hasColon := strings.Cut(version, ":")
	epoch := big.NewInt(0)
	if hasColon {
		if _, ok := epoch.SetString(epochStr, 10); !ok {
			return "", fmt.Errorf("invalid epoch: %s", epochStr)
		}
		version = rest
	}
	// strip out the revision suffix to avoid potential confusion in computation
	if i := strings.LastIndex(version, "-"); i >= 0 {
		version = version[:i]
	}

	// Versions are treated as alternating digit/non-digit strings.
	parts := implicitSplitRegex.FindAllString(version, -1)
	var comps []*big.Int

	if len(parts) > 0 && !isDecimal(parts[0]) {
		// dpkg versions are actually required to start with numbers.
		// For some reason, semantic just treats these invalid versions as greater.
		if !strings.HasPrefix(parts[0], "~") {
			comps = append(comps, big.NewInt(100000000))
		}
	} else {
		for i := 0; i < len(parts); i += 2 {
			p := parts[i]
			if !isDecimal(p) {
				break
			}
			bi := new(big.Int)
			bi.SetString(p, 10)
			comps = append(comps, bi)

			if i+1 >= len(parts) {
				break
			}
			sep := parts[i+1]
			// We treat the exact string '.' as a digit separator.
			if sep == "." {
				continue
			}

			// semantic treats all letters less than all non-letters,
			// but allows all non-letters.
			firstChar := sep[0]
			switch {
			case firstChar >= 'A' && firstChar <= 'Z',
				firstChar >= 'a' && firstChar <= 'z',
				firstChar < '.',
				firstChar == '~':
				// These are allowed characters that do not trigger overflow.
			case strings.HasPrefix(sep, ".~"):
				// "0.~" < "0."
			default:
				// Trigger an overflow because these characters are considered
				// greater than a single dot separator
				comps = append(comps, big.NewInt(100000000))
			}

			break
		}
	}

	return coarseFromInts(epoch, comps...), nil
}

func (e dpkgEcosystem) IsSemver() bool {
	return false
}
