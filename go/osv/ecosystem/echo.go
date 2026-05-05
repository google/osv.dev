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

import "strings"

// echoEcosystem is the Echo container security ecosystem.
//
// Echo provides secured packages across multiple ecosystems:
//   - Echo        - Debian-based packages (dpkg versioning)
//   - Echo:PyPI   - Python packages (PyPI/PEP 440 versioning)
//
// Versioning is delegated to the underlying ecosystem helper.
type echoEcosystem struct {
	Ecosystem
}

func echoFactory(p *Provider, suffix string) Ecosystem {
	if strings.EqualFold(suffix, "pypi") {
		return echoEcosystem{Ecosystem: pypiEcosystem{p: p}}
	}

	return echoEcosystem{Ecosystem: dpkgEcosystem{}}
}
