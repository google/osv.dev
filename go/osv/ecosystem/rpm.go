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
	"regexp"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// rpmEcosystem is an ecosystem for ecosystems using Red Hat Package Manager versioning.
type rpmEcosystem struct{}

var _ Ecosystem = rpmEcosystem{}

func (e rpmEcosystem) Parse(version string) (Version, error) {
	return SemanticVersionWrapper[semantic.RedHatVersion]{semantic.ParseRedHatVersion(version)}, nil
}

var rpmCoarseVersioner = CoarseVersioner{
	Separators:    regexp.MustCompile(`[^0-9A-Za-z~^-]`),
	Truncate:      regexp.MustCompile(`[~^-]`),
	ImplicitSplit: true,
	EmptyAs:       nil,
}

func (e rpmEcosystem) Coarse(version string) (string, error) {
	epochStr, rest, hasColon := strings.Cut(version, ":")
	epoch := 0
	if hasColon {
		if !isDecimal(epochStr) {
			// epoch is not a number, treat it as 0
			return rpmCoarseVersioner.Format(0, version), nil
		}
		epochStr = strings.TrimLeft(epochStr, "0")
		if epochStr == "" {
			epochStr = "0"
		}
		if len(epochStr) > 2 {
			// epoch is > 99, return maximum coarse version
			return "99:99999999.99999999.99999999", nil
		}
		var err error
		epoch, err = strconv.Atoi(epochStr)
		if err != nil {
			// we've validated the string, so this should be unreachable
			return "", err
		}
		version = rest
	}

	return rpmCoarseVersioner.Format(epoch, version), nil
}

func (e rpmEcosystem) IsSemver() bool {
	return false
}
