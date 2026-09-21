package strategies

import (
	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// GitCommitStrategy handles git commit versions by treating them as standalone git commits.
//
// Example CVE Record:
//
//	{
//	    "version": "deadbeefcafebabe0123456789abcdef01234567",
//	    "status": "affected",
//	    "versionType": "git"
//	}
//
// Resulting OSV Range: [introduced: "deadbeef...", last_affected: "deadbeef..."]
type GitCommitStrategy struct{}

func (s *GitCommitStrategy) Name() string {
	return "GitCommit"
}

func (s *GitCommitStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}
	if ToVersionRangeType(vers.VersionType) != VersionRangeTypeGit {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Git commit version found %v", vers.Version)
	vr := []*osvschema.Range{c.BuildGitVersionRange(vers.Version, vers.Version, "", affected.Repo)}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceGit)
	for i := range rwms {
		rwms[i].Metadata.Versions = []string{vers.Version}
	}

	return rwms, VersionRangeTypeGit, true
}

// GitCommitIntroducedOnlyStrategy treats a git commit version as an introduced-only point (used by Linux kernel).
//
// Example CVE Record (Linux Kernel git commits):
//
//	{
//	    "version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2",
//	    "status": "affected",
//	    "versionType": "git"
//	}
//
// Resulting OSV Range: [introduced: "1da177e4c..."]
type GitCommitIntroducedOnlyStrategy struct{}

func (s *GitCommitIntroducedOnlyStrategy) Name() string {
	return "GitCommitIntroducedOnly"
}

func (s *GitCommitIntroducedOnlyStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	if vers.Status != "affected" {
		return nil, VersionRangeTypeUnknown, false
	}
	if ToVersionRangeType(vers.VersionType) != VersionRangeTypeGit {
		return nil, VersionRangeTypeUnknown, false
	}
	if !vulns.CheckQuality(vers.Version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Git commit introduced found %v", vers.Version)
	vr := []*osvschema.Range{c.BuildGitVersionRange(vers.Version, "", "", affected.Repo)}

	return c.ToRangeWithMetadata(vr, models.VersionSourceGit), VersionRangeTypeGit, true
}
