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
	"regexp"
	"strings"
)

// linuxVersionRegex matches upstream Linux kernel release and release-candidate
// versions, e.g. "6.1.100", "v6.1.100", "6.1", "2.6.39.2", "6.1-rc1", or "v5.12-rc1-dontuse".
var linuxVersionRegex = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)(?:-rc(\d+)(?:-([0-9A-Za-z._-]+))?)?$`)

type linuxEcosystem struct{}

var _ Ecosystem = linuxEcosystem{}

type linuxVersion struct {
	components []*big.Int
	rc         *big.Int // nil for final releases, which sort after any -rcN of the same components
	rcExtra    string   // optional suffix after -rcN (e.g. "dontuse" in "v5.12-rc1-dontuse")
}

func (v linuxVersion) Compare(other Version) (int, error) {
	otherV, ok := other.(linuxVersion)
	if !ok {
		return 0, ErrVersionEcosystemMismatch
	}

	maxLen := max(len(v.components), len(otherV.components))
	for i := range maxLen {
		a := bigZero
		if i < len(v.components) {
			a = v.components[i]
		}
		b := bigZero
		if i < len(otherV.components) {
			b = otherV.components[i]
		}
		if c := a.Cmp(b); c != 0 {
			return c, nil
		}
	}

	// Final releases (rc == nil) sort after release candidates (rc != nil).
	switch {
	case v.rc == nil && otherV.rc == nil:
		return 0, nil
	case v.rc == nil:
		return 1, nil
	case otherV.rc == nil:
		return -1, nil
	}

	if c := v.rc.Cmp(otherV.rc); c != 0 {
		return c, nil
	}

	return strings.Compare(v.rcExtra, otherV.rcExtra), nil
}

func parseLinuxVersion(version string) (linuxVersion, error) {
	m := linuxVersionRegex.FindStringSubmatch(version)
	if m == nil {
		return linuxVersion{}, fmt.Errorf("invalid Linux kernel version: %q", version)
	}

	rawParts := strings.Split(m[1], ".")
	comps := make([]*big.Int, 0, len(rawParts))
	for _, p := range rawParts {
		bi, ok := new(big.Int).SetString(p, 10)
		if !ok {
			return linuxVersion{}, fmt.Errorf("invalid numeric component %q in Linux kernel version %q", p, version)
		}
		comps = append(comps, bi)
	}

	// Strip trailing zero components so e.g. "6.1" and "6.1.0" have identical canonical form.
	for len(comps) > 1 && comps[len(comps)-1].Cmp(bigZero) == 0 {
		comps = comps[:len(comps)-1]
	}

	var rc *big.Int
	if m[2] != "" {
		var ok bool
		rc, ok = new(big.Int).SetString(m[2], 10)
		if !ok {
			return linuxVersion{}, fmt.Errorf("invalid rc number %q in Linux kernel version %q", m[2], version)
		}
	}

	return linuxVersion{
		components: comps,
		rc:         rc,
		rcExtra:    m[3],
	}, nil
}

func (linuxEcosystem) Parse(version string) (Version, error) {
	return parseLinuxVersion(version)
}

func (linuxEcosystem) Coarse(version string) (string, error) {
	if version == "0" {
		return coarseFromInts(bigZero, bigZero, bigZero, bigZero), nil
	}
	parsed, err := parseLinuxVersion(version)
	if err != nil {
		return "", err
	}

	return coarseFromInts(bigZero, parsed.components...), nil
}

func (linuxEcosystem) IsSemver() bool {
	return false
}
