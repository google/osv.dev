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

// tuxcareEcosystem represents "TuxCare:<ecosystem>" advisories. It delegates
// version handling to the inner ecosystem, resolved lazily via the Provider
// so that this factory can be registered in the ecosystems map without
// creating a package-init cycle.
type tuxcareEcosystem struct {
	p      *Provider
	suffix string
}

var _ Ecosystem = tuxcareEcosystem{}

func tuxcareFactory(p *Provider, suffix string) Ecosystem {
	innerName, _, _ := strings.Cut(suffix, ":")
	if suffix == "" || innerName == string(osvconstants.EcosystemTuxCare) {
		// Bare "TuxCare" or nested "TuxCare:TuxCare:..." is malformed.
		return nil
	}

	return tuxcareEcosystem{p: p, suffix: suffix}
}

// resolve looks up the inner ecosystem on demand. Inner is unwrapped to avoid
// double-wrapping the resulting Version (which would fail to compare against
// a singly-wrapped Version from the same inner ecosystem).
func (e tuxcareEcosystem) resolve() (Ecosystem, error) {
	inner, ok := e.p.Get(e.suffix)
	if !ok {
		return nil, fmt.Errorf("TuxCare: unknown inner ecosystem %q", e.suffix)
	}

	return unwrap(inner), nil
}

func (e tuxcareEcosystem) Parse(version string) (Version, error) {
	inner, err := e.resolve()
	if err != nil {
		return nil, err
	}

	return inner.Parse(version)
}

func (e tuxcareEcosystem) Coarse(version string) (string, error) {
	inner, err := e.resolve()
	if err != nil {
		return "", err
	}

	return inner.Coarse(version)
}

// IsSemver always returns false: TuxCare advisories should not have their
// affected[].ranges[].type converted from ECOSYSTEM to SEMVER, regardless of
// the inner ecosystem's behavior.
func (e tuxcareEcosystem) IsSemver() bool {
	return false
}

// unwrap strips the wrapper added by Provider.Get, so callers that wrap us
// again don't produce a doubly-wrapped Version.
func unwrap(e Ecosystem) Ecosystem {
	switch w := e.(type) {
	case *ecosystemWrapper:
		return w.Ecosystem
	case *enumerableWrapper:
		return w.Enumerable
	}

	return e
}
