# Vuln feeds
This searches a NVD CVE JSON feed for relevant packages and creates
vulnerability entries in the same easy-to-consume format that OSV uses.

See the relevant subdirectories for more details specific to that package
ecosystem.

## Package name matching
CVE entries do not provide an easy mapping to the exact package name used in a
package manager, so we dump and compare reference URLs for the package against
reference URLs used in the CVE, in addition to some other heuristics to avoid
false positives.

## Extracting affected versions and commits
Where possible, we try to extract affected version ranges from descriptions and
other fields, and extract commit hashes from e.g. GitHub links.
