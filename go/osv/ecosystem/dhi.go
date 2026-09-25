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
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// dhiEcosystem represents "Docker Hardened Images:<lineage>:<release>"
// advisories (e.g. "Docker Hardened Images:Alpine:3.23",
// "Docker Hardened Images:Debian:trixie"). DHI OS packages are repackaged
// Alpine (apk) and Debian (dpkg) packages that keep their upstream version
// syntax (e.g. "8.4.0-r0", "7.88.1-10+deb13u2"), so version handling delegates
// to the lineage ecosystem named in the suffix, resolved lazily via the
// Provider to avoid a package-init cycle.
type dhiEcosystem struct {
	p      *Provider
	suffix string
}

var _ Ecosystem = dhiEcosystem{}

func dhiFactory(p *Provider, suffix string) Ecosystem {
	lineage, _, _ := strings.Cut(suffix, ":")
	if suffix == "" || lineage == string(osvconstants.EcosystemDockerHardenedImages) {
		// Bare "Docker Hardened Images" or a self-referential suffix is malformed.
		return nil
	}

	return dhiEcosystem{p: p, suffix: suffix}
}

// resolve looks up the lineage ecosystem named by the suffix (e.g. "Alpine:3.23"
// or "Debian:trixie") on demand. Inner is unwrapped to avoid double-wrapping the
// resulting Version (which would fail to compare against a singly-wrapped
// Version from the same inner ecosystem).
func (e dhiEcosystem) resolve() (Ecosystem, error) {
	inner, ok := e.p.Get(e.suffix)
	if !ok {
		return nil, fmt.Errorf("unknown Docker Hardened Images lineage ecosystem %q", e.suffix)
	}

	return unwrap(inner), nil
}

func (e dhiEcosystem) Parse(version string) (Version, error) {
	inner, err := e.resolve()
	if err != nil {
		return nil, err
	}

	return inner.Parse(version)
}

func (e dhiEcosystem) Coarse(version string) (string, error) {
	inner, err := e.resolve()
	if err != nil {
		return "", err
	}

	return inner.Coarse(version)
}

// IsSemver always returns false: DHI advisories use ECOSYSTEM ranges, and DHI
// versions follow apk/dpkg ordering rather than SemVer.
func (e dhiEcosystem) IsSemver() bool {
	return false
}
