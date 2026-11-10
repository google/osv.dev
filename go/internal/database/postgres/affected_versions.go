// Package postgres implements the PostgreSQL database store for OSV.
package postgres

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/osvutil"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	MinCoarseVersion = "00:00000000.00000000.00000000"
	MaxCoarseVersion = "99:99999999.99999999.99999999"
)

type AffectedEvent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AffectedVersionRow struct {
	VulnID        string
	Name          string
	BaseEcosystem string
	Ecosystems    []string
	CoarseMin     string
	CoarseMax     string
	Versions      []string
	EventsJSON    []byte
}

var ubuntuReplacer = strings.NewReplacer(":Pro", "", ":LTS", "")

func removeVariants(eco string) string {
	if strings.HasPrefix(eco, "Ubuntu") {
		return ubuntuReplacer.Replace(eco)
	}

	return ""
}

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

// ComputeAffectedVersions computes the affected_versions rows for a vulnerability.
func ComputeAffectedVersions(vuln *osvschema.Vulnerability) ([]AffectedVersionRow, error) {
	if vuln.GetWithdrawn() != nil {
		return nil, nil
	}

	var res []AffectedVersionRow

	for _, affected := range vuln.GetAffected() {
		var allPkgEcosystems []string
		var baseEcosystem string
		pkgEcosystem := affected.GetPackage().GetEcosystem()
		if pkgEcosystem != "" {
			allPkgEcosystems = []string{pkgEcosystem}
			baseEcosystem, _, _ = strings.Cut(pkgEcosystem, ":")
			if baseEcosystem != pkgEcosystem {
				allPkgEcosystems = append(allPkgEcosystems, baseEcosystem)
			}
			if v := removeVariants(pkgEcosystem); v != "" {
				allPkgEcosystems = append(allPkgEcosystems, v)
			}

			slices.Sort(allPkgEcosystems)
			allPkgEcosystems = slices.Compact(allPkgEcosystems)
		}

		pkgName := affected.GetPackage().GetName()
		eHelper, exists := ecosystem.DefaultProvider.Get(pkgEcosystem)
		if exists {
			pkgName = ecosystem.NormalizePackageName(eHelper, pkgName)
		}
		pkgStart := len(res)

		var gitRepos []string
		hasAffected := false

		for _, r := range affected.GetRanges() {
			if r.GetType() == osvschema.Range_GIT {
				if r.GetRepo() != "" {
					gitRepos = append(gitRepos, normalizeRepo(r.GetRepo()))
				}

				continue
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

			rangeEvents := make([]AffectedEvent, 0, len(events))
			for _, e := range events {
				rangeEvents = append(rangeEvents, AffectedEvent{Type: e.Type.String(), Value: e.Version})
			}

			coarseMin := MinCoarseVersion
			coarseMax := MaxCoarseVersion

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

			eventsJSON, err := json.Marshal(rangeEvents)
			if err != nil {
				return nil, err
			}

			if len(allPkgEcosystems) > 0 {
				res = append(res, AffectedVersionRow{
					VulnID:        vuln.GetId(),
					Name:          pkgName,
					BaseEcosystem: baseEcosystem,
					Ecosystems:    allPkgEcosystems,
					CoarseMin:     coarseMin,
					CoarseMax:     coarseMax,
					EventsJSON:    eventsJSON,
				})
			}
		}

		versions := affected.GetVersions()
		if pkgName != "" && len(versions) > 0 && len(allPkgEcosystems) > 0 {
			hasAffected = true
			coarseMin := MinCoarseVersion
			coarseMax := MaxCoarseVersion

			if exists {
				var allCoarse []string
				for _, v := range versions {
					cm, err := eHelper.Coarse(v)
					if err != nil {
						break
					}
					allCoarse = append(allCoarse, cm)
				}
				if len(allCoarse) == len(versions) {
					slices.Sort(allCoarse)
					coarseMin = allCoarse[0]
					coarseMax = allCoarse[len(allCoarse)-1]
				}
			}

			res = append(res, AffectedVersionRow{
				VulnID:        vuln.GetId(),
				Name:          pkgName,
				BaseEcosystem: baseEcosystem,
				Ecosystems:    allPkgEcosystems,
				CoarseMin:     coarseMin,
				CoarseMax:     coarseMax,
				Versions:      versions,
			})
		}

		if pkgName != "" && !hasAffected && len(allPkgEcosystems) > 0 {
			// We have a package that does not have any affected ranges or versions,
			// which doesn't really make sense.
			// Add an empty AffectedVersions entry so that this vuln is returned when
			// querying the API with no version specified.
			res = append(res, AffectedVersionRow{
				VulnID:        vuln.GetId(),
				Name:          pkgName,
				BaseEcosystem: baseEcosystem,
				Ecosystems:    allPkgEcosystems,
				CoarseMin:     MinCoarseVersion,
				CoarseMax:     MaxCoarseVersion,
			})
		}

		// Also index the package under its match name when that differs, so that
		// other spellings the registry treats as the same package find it.
		if exists && pkgName != "" {
			if matchName := ecosystem.NormalizeMatchName(eHelper, pkgName); matchName != pkgName {
				for _, av := range res[pkgStart:] {
					av.Name = matchName
					res = append(res, av)
				}
			}
		}

		if len(gitRepos) > 0 {
			// If we have GIT ranges, always add a GIT entry for each unique repository.
			// Even if affected.versions is empty, we still want to return this vuln
			// for the API queries with no versions specified.
			slices.Sort(gitRepos)
			gitRepos = slices.Compact(gitRepos)
			gitVersions := versions
			if gitVersions == nil {
				gitVersions = []string{}
			}
			for _, repo := range gitRepos {
				res = append(res, AffectedVersionRow{
					VulnID:        vuln.GetId(),
					Name:          repo,
					BaseEcosystem: "GIT",
					Ecosystems:    []string{"GIT"},
					CoarseMin:     MinCoarseVersion,
					CoarseMax:     MaxCoarseVersion,
					Versions:      gitVersions,
				})
			}
		}
	}

	return res, nil
}
