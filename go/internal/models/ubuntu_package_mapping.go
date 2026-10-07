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

package models

import (
	"context"
	"strings"
)

var ubuntuVariantReplacer = strings.NewReplacer(":Pro", "", ":LTS", "")

// NormalizeUbuntuEcosystem normalizes an Ubuntu ecosystem string by removing
// optional ":Pro" and ":LTS" modifiers (e.g. "Ubuntu:24.04:LTS" -> "Ubuntu:24.04").
func NormalizeUbuntuEcosystem(ecosystem string) string {
	if strings.HasPrefix(ecosystem, "Ubuntu") {
		return ubuntuVariantReplacer.Replace(ecosystem)
	}

	return ecosystem
}

// IsValidUbuntuReleaseEcosystem reports whether an ecosystem string (after normalization)
// represents a valid Ubuntu release ecosystem with a non-empty release suffix (e.g. "Ubuntu:22.04").
func IsValidUbuntuReleaseEcosystem(ecosystem string) bool {
	normalized := NormalizeUbuntuEcosystem(ecosystem)
	suffix, ok := strings.CutPrefix(normalized, "Ubuntu:")
	if !ok || suffix == "" || strings.ContainsAny(suffix, " \t\n\r") {
		return false
	}

	return !strings.Contains(suffix, "::") && !strings.HasPrefix(suffix, ":") && !strings.HasSuffix(suffix, ":")
}

// UbuntuPackageKey uniquely identifies an Ubuntu binary package within a specific Ubuntu release ecosystem.
type UbuntuPackageKey struct {
	Ecosystem  string
	BinaryName string
}

// UbuntuPackageMapping represents the mapping from an Ubuntu ecosystem and binary package name
// to its corresponding source package names.
type UbuntuPackageMapping struct {
	Ecosystem   string
	BinaryName  string
	SourceNames []string
}

// UbuntuPackageMappingStore abstracts database operations for querying and updating
// Ubuntu binary-to-source package name mappings.
type UbuntuPackageMappingStore interface {
	// GetMulti retrieves mappings for a slice of (ecosystem, binary_name) keys.
	// For any key not found, the returned UbuntuPackageMapping has an empty SourceNames slice.
	// This results in a 1:1 mapping of input keys to the returned UbuntuPackageMapping slice.
	GetMulti(ctx context.Context, keys []UbuntuPackageKey) ([]*UbuntuPackageMapping, error)

	// PutMulti creates or updates package mappings for multiple (ecosystem, binary_name) pairs.
	PutMulti(ctx context.Context, mappings []*UbuntuPackageMapping) error
}
