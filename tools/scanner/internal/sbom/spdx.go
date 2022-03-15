package sbom

import (
	"fmt"
	"io"

	"github.com/spdx/tools-golang/jsonloader"
)

type SPDX struct{}

func (s *SPDX) Name() string {
	return "SPDX"
}

func (s *SPDX) GetPackages(r io.Reader, callback func(Identifier) error) error {
	doc, err := jsonloader.Load2_2(r)
	if err != nil {
		return fmt.Errorf("%w: %v", InvalidFormat, err)
	}

	for _, p := range doc.Packages {
		for _, r := range p.PackageExternalReferences {
			if r.RefType == "purl" {
				err := callback(Identifier{
					PURL: r.Locator,
				})
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
