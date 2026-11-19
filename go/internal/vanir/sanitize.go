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

package vanir

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	maxCommitsPerRepo        = 64 // Matches gitter's maxCommitPackCommits
	maxSignaturesPerAffected = 256
	maxSignaturesJSONBytes   = 2 << 20 // 2 MiB per vulnerability record
	maxSigIDLen              = 256
	maxSigVersionLen         = 64
	maxSigSourceLen          = 2048
	maxSigFileLen            = 2048
	maxSigFunctionLen        = 1024
	maxSigHashLen            = 128
	maxSigLineHashes         = 10000
	maxSigMatchVersions      = 1024
	maxSigVersionItemLen     = 256
)

var (
	commitHashRegex     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	shortCommitHexRegex = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)
	gitilesRefRegex     = regexp.MustCompile(`^[0-9a-zA-Z][0-9a-zA-Z._-]{0,127}$`)
	cgnatPrefix         = netip.MustParsePrefix("100.64.0.0/10")
	nat64Prefix         = netip.MustParsePrefix("64:ff9b::/96")

	forbiddenHostSuffixes = []string{
		".localhost",
		".local",
		".internal",
		".home.arpa",
		".svc",
		".cluster.local",
		".lan",
		".corp",
		".intranet",
		".goog",
	}

	allowedAndroidFixHosts = map[string]bool{
		"android.googlesource.com": true,
		"git.codelinaro.org":       true,
		"source.codeaurora.org":    true,
	}

	androidEcosystemBases = map[string]bool{
		"Android": true,
		"Pixel":   true,
		"Wear":    true,
	}

	allowedSigTopLevelKeys = map[string]bool{
		"id":                           true,
		"signature_type":               true,
		"signature_version":            true,
		"source":                       true,
		"target":                       true,
		"digest":                       true,
		"deprecated":                   true,
		"exact_target_file_match_only": true,
		"match_only_versions":          true,
	}

	allowedTargetKeys = map[string]bool{
		"file":                 true,
		"function":             true,
		"truncated_path_level": true,
	}

	allowedFunctionDigestKeys = map[string]bool{
		"function_hash": true,
		"length":        true,
	}

	allowedLineDigestKeys = map[string]bool{
		"line_hashes": true,
		"threshold":   true,
	}
)

func isCanonicalAndroidID(id string) bool {
	return strings.HasPrefix(id, "ASB-A-") ||
		strings.HasPrefix(id, "PUB-A-") ||
		strings.HasPrefix(id, "A-")
}

func ecosystemBaseName(eco string) string {
	base, _, _ := strings.Cut(eco, ":")
	return base
}

func looksLikeNumericLabel(label string) bool {
	if label == "" {
		return false
	}
	if strings.HasPrefix(label, "0x") || strings.HasPrefix(label, "0X") {
		if len(label) == 2 {
			return false
		}
		for i := 2; i < len(label); i++ {
			c := label[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}

		return true
	}
	for i := range len(label) {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}

	return true
}

func isForbiddenHost(host string) bool {
	if host == "" {
		return true
	}

	// Check literal IP addresses first (covers IPv4, IPv6, IPv4-mapped IPv6, and zone IDs).
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if addr.IsLoopback() ||
			addr.IsUnspecified() ||
			addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() ||
			addr.IsMulticast() ||
			addr.IsPrivate() ||
			cgnatPrefix.Contains(addr) ||
			nat64Prefix.Contains(addr) {
			return true
		}

		return false
	}

	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	// Reject single-label hostnames (e.g. "localhost", "metadata", K8s service names like
	// "gitter-service", and decimal/hex IP encodings like "2130706433" or "0x7f000001").
	if !strings.Contains(lower, ".") {
		return true
	}
	for _, suffix := range forbiddenHostSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	// Reject shorthand/octal/hex dotted IPv4 encodings (e.g. "127.1", "0177.0.0.1", "0xa9.0xfe.0xa9.0xfe")
	// that netip.ParseAddr rejects but libcurl/git resolve as IPs. No valid public DNS TLD is numeric/hex.
	lastDot := strings.LastIndexByte(lower, '.')
	if lastDot >= 0 && looksLikeNumericLabel(lower[lastDot+1:]) {
		return true
	}

	return false
}

func hasControlOrWhitespace(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			return true
		}
	}

	return false
}

func validateGitRepoURL(raw string) (string, bool) {
	if raw == "" || strings.HasPrefix(raw, "-") || hasControlOrWhitespace(raw) || strings.Contains(raw, "@") {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if scheme == "git" && strings.EqualFold(u.Hostname(), "github.com") {
		scheme = "https"
	}
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	if u.User != nil {
		return "", false
	}
	if isForbiddenHost(u.Hostname()) {
		return "", false
	}
	if u.Path == "" || u.Path == "/" {
		return "", false
	}

	u.Scheme = scheme
	u.Host = host
	u.RawQuery = ""
	u.Fragment = ""

	return u.String(), true
}

func validateAndroidFixURL(raw string) bool {
	if raw == "" || strings.HasPrefix(raw, "-") || hasControlOrWhitespace(raw) || strings.Contains(raw, "@") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}

	host := strings.ToLower(u.Hostname())
	if !allowedAndroidFixHosts[host] {
		return false
	}

	switch host {
	case "android.googlesource.com":
		if u.RawQuery != "" {
			return false
		}
		repoPath, ref, ok := strings.Cut(u.Path, "/+/")
		if !ok || repoPath == "" || repoPath == "/" {
			return false
		}
		ref = strings.TrimSuffix(ref, "/")

		return gitilesRefRegex.MatchString(ref)

	case "git.codelinaro.org":
		if u.RawQuery != "" || !strings.HasPrefix(u.Path, "/clo/") {
			return false
		}
		_, commitPart, ok := strings.Cut(u.Path, "/commit/")
		if !ok {
			return false
		}
		commitPart = strings.TrimSuffix(commitPart, "/")

		return shortCommitHexRegex.MatchString(commitPart)

	case "source.codeaurora.org":
		if !strings.HasPrefix(u.Path, "/quic/") {
			return false
		}
		trimmedPath := strings.TrimSuffix(u.Path, "/")
		if !strings.HasSuffix(trimmedPath, "/commit") {
			return false
		}
		q := u.Query()

		return shortCommitHexRegex.MatchString(q.Get("id"))

	default:
		return false
	}
}

// SanitizeForVanir clones v and strips/validates attacker-controlled fields before sending the
// record to Vanir. It returns:
//   - sanitizedVuln: the sanitized clone safe to pass to Vanir
//   - gitTargets: map of validated Git repo URL -> deduplicated sorted fixed commit hashes
//   - needsNetwork: true when canonical Android fixes require direct network access
func SanitizeForVanir(v *osvschema.Vulnerability) (*osvschema.Vulnerability, map[string][]string, bool) {
	sanitized, gitTargets, needsNetwork, _ := sanitizeForVanirWithIndexMap(v)
	return sanitized, gitTargets, needsNetwork
}

// sanitizeForVanirWithIndexMap performs the same sanitization as SanitizeForVanir and also
// returns indexMap where indexMap[sanitizedAffectedIdx] == originalAffectedIdx so stripped
// affected[] entries never shift signature indices on the original vulnerability record.
func sanitizeForVanirWithIndexMap(v *osvschema.Vulnerability) (*osvschema.Vulnerability, map[string][]string, bool, []int) {
	if v == nil {
		return nil, map[string][]string{}, false, nil
	}

	clone := proto.CloneOf(v)
	// Strip free-text / unused fields to minimize payload and parser exposure.
	clone.Summary = ""
	clone.Details = ""
	clone.References = nil
	clone.Credits = nil

	canonicalAndroid := isCanonicalAndroidID(clone.GetId())
	gitTargetSets := make(map[string]map[string]struct{})
	needsNetwork := false

	keptAffected := make([]*osvschema.Affected, 0, len(clone.GetAffected()))
	indexMap := make([]int, 0, len(clone.GetAffected()))

	for origIdx, aff := range clone.GetAffected() {
		if aff == nil {
			continue
		}

		ecoBase := ecosystemBaseName(aff.GetPackage().GetEcosystem())
		isAndroidEco := androidEcosystemBases[ecoBase]

		if isAndroidEco && !canonicalAndroid {
			// Block AndroidCodeExtractor smuggling from non-Android advisories.
			continue
		}

		if isAndroidEco && canonicalAndroid {
			if ecoSpec := aff.GetEcosystemSpecific(); ecoSpec != nil && ecoSpec.GetFields() != nil {
				if fixesVal, ok := ecoSpec.GetFields()["fixes"]; ok {
					var validFixes []*structpb.Value
					for _, item := range fixesVal.GetListValue().GetValues() {
						fixURL := item.GetStringValue()
						if validateAndroidFixURL(fixURL) {
							validFixes = append(validFixes, structpb.NewStringValue(fixURL))
						}
					}
					if len(validFixes) > 0 {
						ecoSpec.Fields["fixes"] = structpb.NewListValue(&structpb.ListValue{Values: validFixes})
						needsNetwork = true
					} else {
						delete(ecoSpec.GetFields(), "fixes")
					}
				}
			}
		} else if ecoSpec := aff.GetEcosystemSpecific(); ecoSpec != nil && ecoSpec.GetFields() != nil {
			// Strip ecosystem_specific.fixes on non-Android entries.
			delete(ecoSpec.GetFields(), "fixes")
		}

		if len(aff.GetRanges()) > 0 {
			keptRanges := make([]*osvschema.Range, 0, len(aff.GetRanges()))
			for _, r := range aff.GetRanges() {
				if r == nil {
					continue
				}
				if r.GetType() != osvschema.Range_GIT {
					keptRanges = append(keptRanges, r)
					continue
				}

				repoURL, ok := validateGitRepoURL(r.GetRepo())
				if !ok {
					continue
				}

				validEvents := make([]*osvschema.Event, 0, len(r.GetEvents()))
				for _, ev := range r.GetEvents() {
					fixed := strings.ToLower(ev.GetFixed())
					if fixed == "" || !commitHashRegex.MatchString(fixed) {
						continue
					}
					if gitTargetSets[repoURL] == nil {
						gitTargetSets[repoURL] = make(map[string]struct{})
					}
					if _, exists := gitTargetSets[repoURL][fixed]; !exists && len(gitTargetSets[repoURL]) >= maxCommitsPerRepo {
						continue
					}
					gitTargetSets[repoURL][fixed] = struct{}{}
					validEvents = append(validEvents, &osvschema.Event{Fixed: fixed})
				}

				if len(validEvents) == 0 {
					continue
				}

				r.Repo = repoURL
				r.Events = validEvents
				keptRanges = append(keptRanges, r)
			}
			aff.Ranges = keptRanges
		}

		keptAffected = append(keptAffected, aff)
		indexMap = append(indexMap, origIdx)
	}

	clone.Affected = keptAffected

	gitTargets := make(map[string][]string, len(gitTargetSets))
	for repoURL, commitSet := range gitTargetSets {
		commits := make([]string, 0, len(commitSet))
		for c := range commitSet {
			commits = append(commits, c)
		}
		slices.Sort(commits)
		gitTargets[repoURL] = commits
	}

	return clone, gitTargets, needsNetwork, indexMap
}

func affectedAllowsVanirSignatures(vulnID string, aff *osvschema.Affected) bool {
	if aff == nil {
		return false
	}
	for _, r := range aff.GetRanges() {
		if r.GetType() != osvschema.Range_GIT {
			continue
		}
		if _, ok := validateGitRepoURL(r.GetRepo()); !ok {
			continue
		}
		for _, ev := range r.GetEvents() {
			if commitHashRegex.MatchString(strings.ToLower(ev.GetFixed())) {
				return true
			}
		}
	}
	if isCanonicalAndroidID(vulnID) && androidEcosystemBases[ecosystemBaseName(aff.GetPackage().GetEcosystem())] {
		for _, item := range aff.GetEcosystemSpecific().GetFields()["fixes"].GetListValue().GetValues() {
			if validateAndroidFixURL(item.GetStringValue()) {
				return true
			}
		}
	}

	return false
}

func remapAffectedIndices(sanitized *osvschema.Vulnerability, raw map[string][]any, indexMap []int) (map[string][]any, error) {
	if len(raw) == 0 {
		return map[string][]any{}, nil
	}
	vulnID := sanitized.GetId()
	sanitizedAffected := sanitized.GetAffected()
	remapped := make(map[string][]any, len(raw))
	for idxStr, sigs := range raw {
		sIdx, err := strconv.Atoi(idxStr)
		if err != nil || sIdx < 0 || sIdx >= len(indexMap) || sIdx >= len(sanitizedAffected) {
			return nil, fmt.Errorf("invalid sanitized affected index %q", idxStr)
		}
		if !affectedAllowsVanirSignatures(vulnID, sanitizedAffected[sIdx]) {
			return nil, fmt.Errorf("sanitized affected[%d] has no remaining valid GIT range or Android fix", sIdx)
		}
		origIdxStr := strconv.Itoa(indexMap[sIdx])
		remapped[origIdxStr] = sigs
	}

	return remapped, nil
}

// ValidateSignatures enforces strict bounds, index alignment, ID prefix pinning, and schema
// checks on untrusted signature output returned for a single vulnerability record.
func ValidateSignatures(origVuln *osvschema.Vulnerability, rawAffected map[string][]any) (map[int][]*structpb.Value, error) {
	if origVuln == nil {
		return nil, errors.New("origVuln must not be nil")
	}
	if len(rawAffected) == 0 {
		return map[int][]*structpb.Value{}, nil
	}

	// Enforce 2 MiB serialized JSON cap per vulnerability record.
	serialized, err := json.Marshal(rawAffected)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signatures for size check: %w", err)
	}
	if len(serialized) > maxSignaturesJSONBytes {
		return nil, fmt.Errorf("signatures payload size %d exceeds limit %d bytes", len(serialized), maxSignaturesJSONBytes)
	}

	vulnID := origVuln.GetId()
	affectedSlice := origVuln.GetAffected()
	out := make(map[int][]*structpb.Value, len(rawAffected))

	for idxStr, sigList := range rawAffected {
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 0 || idx >= len(affectedSlice) {
			return nil, fmt.Errorf("affected index %q out of bounds for %s (len=%d)", idxStr, vulnID, len(affectedSlice))
		}
		if !affectedAllowsVanirSignatures(vulnID, affectedSlice[idx]) {
			return nil, fmt.Errorf("affected[%d] for %s does not have a GIT range or valid Android fix", idx, vulnID)
		}
		if len(sigList) > maxSignaturesPerAffected {
			return nil, fmt.Errorf("affected[%d] for %s has %d signatures (max %d)", idx, vulnID, len(sigList), maxSignaturesPerAffected)
		}

		vals := make([]*structpb.Value, 0, len(sigList))
		for i, rawSig := range sigList {
			sigObj, ok := rawSig.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("signature[%d] for %s affected[%d] is not a JSON object", i, vulnID, idx)
			}
			if err := validateSingleSignature(vulnID, sigObj); err != nil {
				return nil, fmt.Errorf("invalid signature[%d] for %s affected[%d]: %w", i, vulnID, idx, err)
			}
			val, err := structpb.NewValue(sigObj)
			if err != nil {
				return nil, fmt.Errorf("failed to convert signature[%d] for %s: %w", i, vulnID, err)
			}
			vals = append(vals, val)
		}
		if len(vals) > 0 {
			out[idx] = vals
		}
	}

	return out, nil
}

func validateSingleSignature(vulnID string, sig map[string]any) error {
	for k := range sig {
		if !allowedSigTopLevelKeys[k] {
			return fmt.Errorf("unexpected top-level key %q", k)
		}
	}

	sigID, ok := sig["id"].(string)
	if !ok || len(sigID) == 0 || len(sigID) > maxSigIDLen || !strings.HasPrefix(sigID, vulnID+"-") {
		return fmt.Errorf("invalid signature id %v (must start with %q)", sig["id"], vulnID+"-")
	}

	sigType, ok := sig["signature_type"].(string)
	if !ok || (sigType != "Function" && sigType != "Line") {
		return fmt.Errorf("invalid signature_type %v", sig["signature_type"])
	}

	sigVersion, ok := sig["signature_version"].(string)
	if !ok || len(sigVersion) == 0 || len(sigVersion) > maxSigVersionLen {
		return fmt.Errorf("invalid signature_version %v", sig["signature_version"])
	}

	if rawSource, exists := sig["source"]; exists {
		src, ok := rawSource.(string)
		if !ok || len(src) > maxSigSourceLen {
			return errors.New("invalid source field")
		}
	}

	if rawDeprecated, exists := sig["deprecated"]; exists {
		if _, ok := rawDeprecated.(bool); !ok {
			return errors.New("deprecated must be a boolean")
		}
	}

	if rawExact, exists := sig["exact_target_file_match_only"]; exists {
		if _, ok := rawExact.(bool); !ok {
			return errors.New("exact_target_file_match_only must be a boolean")
		}
	}

	if rawMatchVersions, exists := sig["match_only_versions"]; exists {
		list, ok := rawMatchVersions.([]any)
		if !ok || len(list) > maxSigMatchVersions {
			return errors.New("invalid match_only_versions")
		}
		for _, item := range list {
			s, ok := item.(string)
			if !ok || len(s) == 0 || len(s) > maxSigVersionItemLen {
				return errors.New("invalid match_only_versions entry")
			}
		}
	}

	target, ok := sig["target"].(map[string]any)
	if !ok {
		return errors.New("missing or non-object target")
	}
	if err := validateSignatureTarget(sigType, target); err != nil {
		return err
	}

	digest, ok := sig["digest"].(map[string]any)
	if !ok {
		return errors.New("missing or non-object digest")
	}
	if err := validateSignatureDigest(sigType, digest); err != nil {
		return err
	}

	return nil
}

func validateSignatureTarget(sigType string, target map[string]any) error {
	for k := range target {
		if !allowedTargetKeys[k] {
			return fmt.Errorf("unexpected target key %q", k)
		}
	}

	file, ok := target["file"].(string)
	if !ok || len(file) == 0 || len(file) > maxSigFileLen {
		return errors.New("invalid target.file")
	}

	rawFn, hasFn := target["function"]
	switch sigType {
	case "Function":
		fn, ok := rawFn.(string)
		if !hasFn || !ok || len(fn) == 0 || len(fn) > maxSigFunctionLen {
			return errors.New("invalid or missing target.function for Function signature")
		}
	case "Line":
		if hasFn {
			return errors.New("unexpected target.function for Line signature")
		}
	}

	if rawLevel, exists := target["truncated_path_level"]; exists {
		lvl, ok := asFiniteFloat(rawLevel)
		if !ok || lvl < 0 || math.Trunc(lvl) != lvl {
			return errors.New("invalid target.truncated_path_level")
		}
	}

	return nil
}

func validateSignatureDigest(sigType string, digest map[string]any) error {
	switch sigType {
	case "Function":
		for k := range digest {
			if !allowedFunctionDigestKeys[k] {
				return fmt.Errorf("unexpected Function digest key %q", k)
			}
		}
		fnHash, ok := digest["function_hash"].(string)
		if !ok || len(fnHash) == 0 || len(fnHash) > maxSigHashLen {
			return errors.New("invalid digest.function_hash")
		}
		length, ok := asFiniteFloat(digest["length"])
		if !ok || length < 0 || math.Trunc(length) != length {
			return errors.New("invalid digest.length")
		}

		return nil

	case "Line":
		for k := range digest {
			if !allowedLineDigestKeys[k] {
				return fmt.Errorf("unexpected Line digest key %q", k)
			}
		}
		rawHashes, ok := digest["line_hashes"].([]any)
		if !ok || len(rawHashes) == 0 || len(rawHashes) > maxSigLineHashes {
			return errors.New("invalid digest.line_hashes")
		}
		for _, item := range rawHashes {
			h, ok := item.(string)
			if !ok || len(h) == 0 || len(h) > maxSigHashLen {
				return errors.New("invalid digest.line_hashes entry")
			}
		}
		threshold, ok := asFiniteFloat(digest["threshold"])
		if !ok || threshold < 0 || threshold > 1 {
			return errors.New("invalid digest.threshold")
		}

		return nil

	default:
		return fmt.Errorf("unsupported signature_type %q", sigType)
	}
}

func asFiniteFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
