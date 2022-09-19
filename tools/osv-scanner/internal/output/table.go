package output

import (
	"log"
	"os"
	"strings"

	"github.com/google/osv.dev/tools/osv-scanner/internal/grouper"
	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/package-url/packageurl-go"
	"golang.org/x/term"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(query osv.BatchedQuery, resp *osv.HydratedBatchedResponse) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(os.Stdout)
	outputTable.AppendHeader(table.Row{"Source", "Ecosystem", "Affected Package", "Installed Version", "Vulnerability ID", "OSV URL"})

	for i, query := range query.Queries {
		if len(resp.Results[i].Vulns) == 0 {
			continue
		}
		for _, group := range grouper.Group(resp.Results[i].Vulns) {
			outputRow := table.Row{query.Source}
			shouldMerge := false
			if query.Commit != "" {
				outputRow = append(outputRow, "GIT", query.Commit, query.Commit)
				shouldMerge = true
			} else if query.Package.PURL != "" {
				parsedPURL, err := packageurl.FromString(query.Package.PURL)
				if err != nil {
					log.Println("Failed to parse purl")
					continue
				}
				purlVersion := parsedPURL.Version
				parsedPURL.Version = ""
				parsedPURL.Qualifiers = []packageurl.Qualifier{}
				outputRow = append(outputRow, "PURL", parsedPURL.ToString(), purlVersion)
				shouldMerge = true
			} else {
				outputRow = append(outputRow, query.Package.Ecosystem, query.Package.Name, query.Version)
			}

			var ids []string
			var links []string

			for _, vuln := range group {
				ids = append(ids, vuln.ID)
				links = append(links, osv.BaseVulnerabilityURL+vuln.ID)
			}

			outputRow = append(outputRow, strings.Join(ids, "\n"), strings.Join(links, "\n"))
			outputTable.AppendRow(outputRow, table.RowConfig{AutoMerge: shouldMerge})
		}
	}

	outputTable.SetStyle(table.StyleRounded)
	outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgBlack}
	outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.Reset}
	// TODO: Leave these here until styling is finalized
	//outputTable.Style().Color.Header = text.Colors{text.FgHiCyan, text.BgBlack}
	//outputTable.Style().Color.Row = text.Colors{text.Reset, text.Reset}
	//outputTable.Style().Options.SeparateRows = true
	//outputTable.Style().Options.SeparateColumns = true
	//outputTable.SetColumnConfigs([]table.ColumnConfig{
	//	{Number: 2, AutoMerge: true, WidthMax: maxCharacters},
	//	{Number: 3, AutoMerge: true, WidthMax: maxCharacters},
	//})

	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil { // If output is a terminal, set max length to width
		outputTable.SetAllowedRowLength(width)
	} // Otherwise don't set max width (e.g. getting piped to a file)
	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
}
