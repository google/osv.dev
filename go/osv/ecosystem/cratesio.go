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

// cratesIOEcosystem is the crates.io ecosystem. It shares semverEcosystem's
// versioning and adds crates.io's package name matching.
type cratesIOEcosystem struct {
	semverEcosystem
}

// MatchPackageName lowercases a crate name and replaces '_' with '-', since
// crates.io treats crate names case-insensitively and treats '-' and '_' as
// equivalent. crates.io only accepts ASCII crate names.
func (e cratesIOEcosystem) MatchPackageName(name string) string {
	return strings.ReplaceAll(asciiToLower(name), "_", "-")
}

var _ PackageNameMatcher = cratesIOEcosystem{}
