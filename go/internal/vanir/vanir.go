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

// Package vanir implements orchestration and domain mutations for Vanir signature generation.
package vanir

import (
	"slices"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	JobName          = "vanir_signatures"
	JobDataLastRun   = "vanir_signatures_last_run"
	JobDataRetryList = "vanir_signatures_retry_list"
)

// AffectedIsKernel returns true if the affected package is the Linux kernel.
func AffectedIsKernel(affected *osvschema.Affected) bool {
	if affected.GetPackage().GetName() == "Kernel" && affected.GetPackage().GetEcosystem() == "Linux" {
		return true
	}
	for _, ar := range affected.GetRanges() {
		if strings.Contains(ar.GetRepo(), "git.kernel.org/pub/scm/linux/kernel/git") {
			return true
		}
	}

	return false
}

// HasGitRanges returns true if any affected entry contains a GIT range.
func HasGitRanges(v *osvschema.Vulnerability) bool {
	for _, affected := range v.GetAffected() {
		for _, r := range affected.GetRanges() {
			if r.GetType() == osvschema.Range_GIT {
				return true
			}
		}
	}

	return false
}

// HasVanirSignatures returns true if any affected entry already has vanir_signatures.
func HasVanirSignatures(v *osvschema.Vulnerability) bool {
	for _, affected := range v.GetAffected() {
		if affected.GetDatabaseSpecific().GetFields()["vanir_signatures"] != nil {
			return true
		}
	}

	return false
}

// ShouldProcess checks whether a vulnerability is eligible for Vanir signature generation.
// If ineligible, it returns false and a short reason string for debug logging.
func ShouldProcess(v *osvschema.Vulnerability) (bool, string) {
	if !HasGitRanges(v) {
		return false, "no GIT affected ranges"
	}
	if slices.ContainsFunc(v.GetAffected(), AffectedIsKernel) {
		return false, "it is a Kernel vulnerability"
	}
	if v.GetWithdrawn() != nil {
		return false, "it is withdrawn"
	}
	if HasVanirSignatures(v) {
		return false, "already has Vanir signatures"
	}

	return true, ""
}

// ApplySignatures returns a models.MutateFunc that injects generated Vanir signatures
// and the vanir_signatures_modified timestamp into the corresponding affected[].database_specific
// entries of a vulnerability record.
func ApplySignatures(sigsByAffectedIdx map[int][]*structpb.Value, now time.Time) models.MutateFunc {
	return func(v *osvschema.Vulnerability) (bool, error) {
		if len(sigsByAffectedIdx) == 0 {
			return false, nil
		}

		utcNow := now.UTC()
		nowISO := utcNow.Format(time.RFC3339)
		changed := false

		for idx, sigs := range sigsByAffectedIdx {
			if len(sigs) == 0 || idx < 0 || idx >= len(v.GetAffected()) {
				continue
			}
			affected := v.GetAffected()[idx]
			if affected.GetDatabaseSpecific() == nil {
				affected.DatabaseSpecific = &structpb.Struct{
					Fields: make(map[string]*structpb.Value),
				}
			} else if affected.GetDatabaseSpecific().GetFields() == nil {
				affected.DatabaseSpecific.Fields = make(map[string]*structpb.Value)
			}

			newListVal := structpb.NewListValue(&structpb.ListValue{Values: sigs})
			existingVal := affected.GetDatabaseSpecific().GetFields()["vanir_signatures"]
			if existingVal != nil && proto.Equal(existingVal, newListVal) {
				continue
			}

			affected.DatabaseSpecific.Fields["vanir_signatures"] = newListVal
			affected.DatabaseSpecific.Fields["vanir_signatures_modified"] = structpb.NewStringValue(nowISO)
			changed = true
		}

		if changed {
			v.Modified = timestamppb.New(utcNow)
		}

		return changed, nil
	}
}
