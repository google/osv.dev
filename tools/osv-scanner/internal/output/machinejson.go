package output

import (
	"encoding/json"
	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
)

type Output struct {
	Results []Result `json:"results"`
}

type Result struct {
	FilePath string `json:"filePath"`
	Packages []Package `json:"packages"`
}

type Package struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Ecosystem       string `json:"ecosystem"`
	Vulnerabilities []osv.Vulnerability `json:"vulnerabilities"`
}

func PrintJSONResults(query osv.BatchedQuery, resp *osv.HydratedBatchedResponse) {
	output := Output{}
	groupedBySource := map[string][]Package{}

	for i, query := range query.Queries {
		response := resp.Results[i]
		if len(response.Vulns) == 0 {
			continue
		}
		groupedBySource[query.Source] = append(groupedBySource[query.Source], Package{
			// TODO: Extract and use some of the logic in morphing PURL into this format
			Name:            query.Package.Name,
			Version:         query.Version,
			Ecosystem:       query.Package.Ecosystem,
			Vulnerabilities: response.Vulns,
		})
	}

	for source, packages := range groupedBySource {
		output.Results = append(output.Results, Result{
			FilePath: source,
			Packages: packages,
		})
	}

	marshal, err := json.MarshalIndent(output,"", "  ")
	if err != nil {
		return
	}
	print(string(marshal))
}
