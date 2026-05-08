package datastore

import (
	"net/url"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/osvutil"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	minCoarseVersion = "00:00000000.00000000.00000000"
	maxCoarseVersion = "99:99999999.99999999.99999999"
)

func normalizeRepo(repoURL string) string {
	// Normalize the repo_url for use with GIT AffectedVersions entities.
	// Removes the scheme/protocol, the .git extension, and trailing slashes.
	if repoURL == "" {
		return ""
	}
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return repoURL
	}
	normalized := parsed.Host + parsed.Path
	normalized = strings.TrimRight(normalized, "/")
	normalized = strings.TrimSuffix(normalized, ".git")

	return normalized
}

func computeAffectedVersions(vuln *osvschema.Vulnerability) []AffectedVersions {
	var res []AffectedVersions

	for _, affected := range vuln.GetAffected() {
		pkgEcosystem := affected.GetPackage().GetEcosystem()
		if pkgEcosystem == "" {
			continue
		}

		allPkgEcosystems := []string{pkgEcosystem}
		normalized, _, _ := strings.Cut(pkgEcosystem, ":")
		if normalized != pkgEcosystem {
			allPkgEcosystems = append(allPkgEcosystems, normalized)
		}
		if v := removeVariants(pkgEcosystem); v != "" {
			allPkgEcosystems = append(allPkgEcosystems, v)
		}

		slices.Sort(allPkgEcosystems)
		allPkgEcosystems = slices.Compact(allPkgEcosystems)

		pkgName := affected.GetPackage().GetName()
		eHelper, exists := ecosystem.DefaultProvider.Get(pkgEcosystem)

		// TODO(michaelkedar): Matching the current behavior of the API,
		// where GIT tags match to the first git repo in the ranges list, even if
		// there are non-git ranges or multiple git repos in a range.
		repoURL := ""
		hasAffected := false

		for _, r := range affected.GetRanges() {
			if r.GetType() == osvschema.Range_GIT && repoURL == "" {
				repoURL = r.GetRepo()
			}
			if r.GetType() != osvschema.Range_ECOSYSTEM && r.GetType() != osvschema.Range_SEMVER {
				continue
			}
			if len(r.GetEvents()) == 0 {
				continue
			}

			hasAffected = true
			var events []osvutil.Event
			for _, e := range r.GetEvents() {
				evt := osvutil.FromSchemaEvent(e)
				if evt.Version != "" {
					events = append(events, evt)
				}
			}

			if exists {
				_ = osvutil.SortEvents(eHelper, events)
			}

			var rangeEvents []AffectedEvent
			for _, e := range events {
				rangeEvents = append(rangeEvents, AffectedEvent{Type: e.Type.String(), Value: e.Version})
			}

			coarseMin := minCoarseVersion
			coarseMax := maxCoarseVersion

			if exists {
				for _, ev := range rangeEvents {
					if ev.Type == "introduced" {
						if cm, err := eHelper.Coarse(ev.Value); err == nil {
							coarseMin = cm
						}
						last := rangeEvents[len(rangeEvents)-1]
						if last.Type != "introduced" {
							if cm, err := eHelper.Coarse(last.Value); err == nil {
								coarseMax = cm
							}
						}

						break
					}
				}
			}

			for _, e := range allPkgEcosystems {
				res = append(res, AffectedVersions{
					VulnID:    vuln.GetId(),
					Ecosystem: e,
					Name:      pkgName,
					Events:    rangeEvents,
					CoarseMin: coarseMin,
					CoarseMax: coarseMax,
				})
			}
		}

		if pkgName != "" && len(affected.GetVersions()) > 0 {
			hasAffected = true
			coarseMin := minCoarseVersion
			coarseMax := maxCoarseVersion

			if exists {
				var allCoarse []string
				for _, v := range affected.GetVersions() {
					if cm, err := eHelper.Coarse(v); err == nil {
						allCoarse = append(allCoarse, cm)
					}
				}
				if len(allCoarse) > 0 {
					slices.Sort(allCoarse)
					coarseMin = allCoarse[0]
					coarseMax = allCoarse[len(allCoarse)-1]
				}
			}

			for _, e := range allPkgEcosystems {
				res = append(res, AffectedVersions{
					VulnID:    vuln.GetId(),
					Ecosystem: e,
					Name:      pkgName,
					Versions:  affected.GetVersions(),
					CoarseMin: coarseMin,
					CoarseMax: coarseMax,
				})
			}
		}

		if pkgName != "" && !hasAffected {
			// We have a package that does not have any affected ranges or versions,
			// which doesn't really make sense.
			// Add an empty AffectedVersions entry so that this vuln is returned when
			// querying the API with no version specified.
			for _, e := range allPkgEcosystems {
				res = append(res, AffectedVersions{
					VulnID:    vuln.GetId(),
					Ecosystem: e,
					Name:      pkgName,
					CoarseMin: minCoarseVersion,
					CoarseMax: maxCoarseVersion,
				})
			}
		}

		if repoURL != "" {
			// If we have a repository, always add a GIT entry.
			// Even if affected.versions is empty, we still want to return this vuln
			// for the API queries with no versions specified.
			res = append(res, AffectedVersions{
				VulnID:    vuln.GetId(),
				Ecosystem: "GIT",
				Name:      normalizeRepo(repoURL),
				Versions:  affected.GetVersions(),
			})
		}
	}

	return res
}
