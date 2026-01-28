package main

import "regexp"

// Following the version requirement specified here: https://github.com/alpinelinux/abuild/blob/master/APKBUILD.5.scd
var validVersionChecker = regexp.MustCompile(
	// Matches "one or more numbers separated by the radix (decimal point)."
	`^(\d+\.)*(\d+)` +
		// the final number may have a single letter following it
		`[a-zA-Z]?` +
		// A suffix may be appended, which must be an underscore followed by
		// alpha, beta, pre, rc, cvs, svn, git, hg, or p,
		// optionally followed by another number.
		// The underscore is actually optional, see: https://gitlab.alpinelinux.org/alpine/abuild/-/issues/10088
		`(_?(?:alpha|beta|rc|pre|cvs|svn|git|hg|p)\d*)?` +
		// This is the revision, which follows the version in security advisories
		`([-\.]r\d+)?$`,
)

func validVersion(ver string) bool {
	return validVersionChecker.MatchString(ver)
}
