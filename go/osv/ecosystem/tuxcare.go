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
	"errors"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// tuxcareEcosystem represents "TuxCare:<ecosystem>" advisories. It delegates
// version handling to the inner ecosystem.
type tuxcareEcosystem struct {
	inner Ecosystem
}

var _ Ecosystem = tuxcareEcosystem{}

// Registered in init() to break an initialization cycle: the ecosystems map
// references tuxcareFactory, which calls Provider.Get, which reads the map.
func init() {
	ecosystems[osvconstants.EcosystemTuxCare] = tuxcareFactory
}

// tuxcareFactory builds a tuxcareEcosystem by recursively resolving the inner
// ecosystem via the provider. Returns nil when the suffix is empty or names
// another TuxCare (so Provider.Get reports the ecosystem as unknown).
func tuxcareFactory(p *Provider, suffix string) Ecosystem {
	innerName, _, _ := strings.Cut(suffix, ":")
	if suffix == "" || innerName == string(osvconstants.EcosystemTuxCare) {
		return nil
	}
	inner, ok := p.Get(suffix)
	if !ok {
		return nil
	}

	return tuxcareEcosystem{inner: unwrap(inner)}
}

// unwrap strips the version-zero wrapper added by Provider.Get, so callers
// that wrap us again don't produce a doubly-wrapped Version (which would
// fail to compare against a singly-wrapped Version from the same inner
// ecosystem).
func unwrap(e Ecosystem) Ecosystem {
	switch w := e.(type) {
	case *ecosystemWrapper:
		return w.Ecosystem
	case *enumerableWrapper:
		return w.Enumerable
	}

	return e
}

func (e tuxcareEcosystem) Parse(version string) (Version, error) {
	if e.inner == nil {
		return nil, errors.New("TuxCare ecosystem has no resolvable inner ecosystem")
	}

	return e.inner.Parse(version)
}

func (e tuxcareEcosystem) Coarse(version string) (string, error) {
	if e.inner == nil {
		return "", errors.New("TuxCare ecosystem has no resolvable inner ecosystem")
	}

	return e.inner.Coarse(version)
}

func (e tuxcareEcosystem) IsSemver() bool {
	if e.inner == nil {
		return false
	}

	return e.inner.IsSemver()
}
