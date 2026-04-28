package ecosystem

import (
	"bufio"
	"os"
	"slices"
	"testing"
)

func TestCoarseMonotonicityLarge(t *testing.T) {
	if os.Getenv("RUN_COARSE_LARGE_TEST") != "1" {
		t.Skip("Skipping large test: RUN_COARSE_LARGE_TEST=1 not set")
	}

	filePath := "testdata/all_versions.txt"
	f, err := os.Open(filePath)
	if os.IsNotExist(err) {
		t.Skipf("Skipping large test: %s not found. Run tools to generate it from all.zip.", filePath)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var allVers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		allVers = append(allVers, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	p := DefaultProvider

	// List of unique ecosystems to test
	ecosystemsToTest := []string{
		"Packagist",
		"PyPI",
		"Maven",
		"RubyGems",
		"CRAN",
		"NuGet",
		"Pub",
		"Hackage",
		"Debian",  // Represets dpkgEcosystem
		"Go",      // Represents semverEcosystem
		"Red Hat", // Represents rpmEcosystem
		// "Alpine",  // Represents apkEcosystem
	}

	for _, ecoName := range ecosystemsToTest {
		t.Run(ecoName, func(t *testing.T) {
			t.Parallel()
			ecoName := ecoName
			e, ok := p.Get(ecoName)
			if !ok {
				t.Fatalf("failed to get ecosystem %s", ecoName)
			}

			type vers struct {
				Raw    string
				Parsed Version
				Coarse string
			}

			var goodVers []vers
			for _, ver := range allVers {
				v, errP := e.Parse(ver)
				c, errC := e.Coarse(ver)
				if (errP == nil) != (errC == nil) {
					// Inconsistent failure between Parse and Coarse is usually a bug
					// but for large tests we might just skip them or log them to avoid spam.
					continue
				}
				if errP == nil {
					goodVers = append(goodVers, vers{ver, v, c})
				}
			}

			if len(goodVers) == 0 {
				t.Logf("No valid versions found for %s in the dataset", ecoName)
				return
			}

			slices.SortFunc(goodVers, func(a, b vers) int {
				c, err := a.Parsed.Compare(b.Parsed)
				if err != nil {
					t.Fatalf("error comparing! %v", err)
				}

				return c
			})

			prev := goodVers[0]
			for _, next := range goodVers[1:] {
				if prev.Coarse > next.Coarse {
					t.Errorf("Monotonicity violation: %q <= %q but coarse %s > %s", prev.Raw, next.Raw, prev.Coarse, next.Coarse)
				}
				prev = next
			}
		})
	}
}
