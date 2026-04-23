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
	"slices"
	"strings"
)

type parsedVersion struct {
	str string
	ver Version
}

// sortVersions sorts a slice of version strings according to the ecosystem's parsing and comparison logic.
// It returns an error if any version string cannot be parsed or compared.
func sortVersions(e Ecosystem, versions []string) ([]string, error) {
	parsed := make([]parsedVersion, 0, len(versions))
	for _, v := range versions {
		p, err := e.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version %s: %w", v, err)
		}
		parsed = append(parsed, parsedVersion{str: v, ver: p})
	}

	var sortErr error
	slices.SortFunc(parsed, func(a, b parsedVersion) int {
		c, err := a.ver.Compare(b.ver)
		if err != nil {
			sortErr = err
		}

		return c
	})

	result := make([]string, 0, len(parsed))
	var last string
	for i, p := range parsed {
		if i > 0 && p.str == last {
			continue
		}
		result = append(result, p.str)
		last = p.str
	}

	return result, sortErr
}

var (
	maxCoarseEpoch = big.NewInt(99)
	maxCoarsePart  = big.NewInt(99999999)
	bigZero        = big.NewInt(0)
)

// CoarseVersioner contains configuration for generating coarse versions.
type CoarseVersioner struct {
	Separators    *regexp.Regexp // Regex for separators (e.g. types using dot notation).
	Truncate      *regexp.Regexp // Regex for characters to truncate after (e.g. prerelease/build suffixes). If nil, no truncation.
	ImplicitSplit bool           // If True, splits on transitions between digits and non-digits.
	EmptyAs       *string        // If not nil, treats empty parts as the given string instead of removing them. If nil, removes them.
}

var implicitSplitRegex = regexp.MustCompile(`\d+|\D+`) // used to split on transition between letter and number

// Format converts a version string into a coarse, lexicographically comparable string.
func (v CoarseVersioner) Format(epoch int, version string) string {
	if version == "0" {
		return coarseFromInts(big.NewInt(int64(epoch)), bigZero, bigZero, bigZero)
	}

	main := version
	if v.Truncate != nil {
		// Truncate off trailing components (e.g. prerelease/build)
		main = v.Truncate.Split(version, 2)[0]
	}

	parts := v.Separators.Split(main, -1)
	if v.ImplicitSplit {
		// Also split on transitions between digits and non-digits
		var splitParts []string
		for _, part := range parts {
			if part == "" {
				splitParts = append(splitParts, "")
				continue
			}
			splitParts = append(splitParts, implicitSplitRegex.FindAllString(part, -1)...)
		}
		parts = splitParts
	}

	filteredParts := make([]string, 0, len(parts))
	// Filter empty parts or treat as zero
	if v.EmptyAs != nil {
		for _, p := range parts {
			if p == "" {
				filteredParts = append(filteredParts, *v.EmptyAs)
			} else {
				filteredParts = append(filteredParts, p)
			}
		}
	} else {
		for _, p := range parts {
			if p != "" {
				filteredParts = append(filteredParts, p)
			}
		}
	}
	parts = filteredParts

	// Extract up to 3 integer components
	var components []*big.Int
	for _, p := range parts {
		if len(components) >= 3 {
			break
		}
		if !isDecimal(p) {
			break
		}
		bi := new(big.Int)
		if _, ok := bi.SetString(p, 10); ok {
			components = append(components, bi)
		} else {
			break
		}
	}

	return coarseFromInts(big.NewInt(int64(epoch)), components...)
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func coarseFromInts(epoch *big.Int, parts ...*big.Int) string {
	// treat nil values as 0
	if epoch == nil {
		epoch = bigZero
	}
	// if, somehow, the epoch is < 0, set whole string to min value
	if epoch.Cmp(bigZero) < 0 {
		return "00:00000000.00000000.00000000"
	}
	// if epoch > maximum, set whole string to max value
	if epoch.Cmp(maxCoarseEpoch) > 0 {
		return "99:99999999.99999999.99999999"
	}
	epochStr := fmt.Sprintf("%02d", epoch.Int64())
	partStrs := make([]string, 0, 3)
	for _, part := range parts {
		if len(partStrs) >= 3 {
			break
		}
		// treat nil values as 0
		if part == nil {
			part = bigZero
		}
		// if, somehow, there's a negative integer part,
		// set it and the remaining parts to 0
		if part.Cmp(bigZero) < 0 {
			for len(partStrs) < 3 {
				partStrs = append(partStrs, "00000000")
			}

			break
		}
		// if the part is above the maximum value,
		// set it and remaining parts to max
		if part.Cmp(maxCoarsePart) > 0 {
			for len(partStrs) < 3 {
				partStrs = append(partStrs, "99999999")
			}

			break
		}
		partInt := part.Int64() // maxPart < int64 max so this is fine
		partStrs = append(partStrs, fmt.Sprintf("%08d", partInt))
	}
	// append 0's if we don't have enough parts
	for len(partStrs) < 3 {
		partStrs = append(partStrs, "00000000")
	}

	return epochStr + ":" + strings.Join(partStrs, ".")
}
