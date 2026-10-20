package ecosystem

import (
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// redHatLightwellFactory builds the Ecosystem for a "Red Hat Lightwell:<base>"
// OSV ecosystem, e.g. "Red Hat Lightwell:Maven" or "Red Hat Lightwell:PyPI".
//
// Red Hat Lightwell republishes upstream artifacts carrying a backport version
// marker (Maven ".rhlw-NNNNN", PyPI "+rhlw.N") that sorts within the base
// ecosystem's own version space, so version semantics delegate to the base
// ecosystem named by the ":" suffix. An unsupported suffix yields a nil
// Ecosystem, which Provider.Get reports as "not found".
func redHatLightwellFactory(p *Provider, suffix string) Ecosystem {
	switch osvconstants.Ecosystem(suffix) {
	case osvconstants.EcosystemMaven:
		return mavenEcosystem{p: p}
	case osvconstants.EcosystemPyPI:
		return pypiEcosystem{p: p}
	default:
		return nil
	}
}
