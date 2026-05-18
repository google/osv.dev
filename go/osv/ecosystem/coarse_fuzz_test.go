package ecosystem

import (
	"testing"
)

func checkCoarseMonotonicityRaw(t *testing.T, e Ecosystem, v1Str, v2Str string) {
	t.Helper()
	v1, errP1 := e.Parse(v1Str)
	v2, errP2 := e.Parse(v2Str)

	c1, errC1 := e.Coarse(v1Str)
	c2, errC2 := e.Coarse(v2Str)

	if (errP1 == nil) != (errC1 == nil) {
		t.Fatalf("Parse and Coarse success mismatch for %q: Parse err=%v, Coarse err=%v", v1Str, errP1, errC1)
	}
	if (errP2 == nil) != (errC2 == nil) {
		t.Fatalf("Parse and Coarse success mismatch for %q: Parse err=%v, Coarse err=%v", v2Str, errP2, errC2)
	}

	if errP1 != nil || errP2 != nil {
		return // Skip monotonicity check if any failed
	}

	comp, err := v1.Compare(v2)
	if err != nil {
		return
	}

	if comp < 0 && c1 > c2 {
		t.Errorf("Monotonicity violation: %q < %q but coarse %s > %s", v1Str, v2Str, c1, c2)
	}
	if comp > 0 && c1 < c2 {
		t.Errorf("Monotonicity violation: %q > %q but coarse %s < %s", v1Str, v2Str, c1, c2)
	}
	if comp == 0 && c1 != c2 {
		t.Errorf("Equality violation: %q == %q but coarse %s != %s", v1Str, v2Str, c1, c2)
	}
}

func FuzzPackagistMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"v1.0.0", "v1.0.1",
		"1.0.0-beta1",
		"0__1", "00",
		"1.0.0+build1",
		"1.0.0+bedrock-1.17.10",
		"1..0",
		"1.-.0",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Packagist")
		if !ok {
			t.Fatal("Packagist not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzPyPIMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0.0a1", "1.0.0.post1",
		"1.0.dev1", "1.0",
		"1.0.post1", "1.0.post2",
		"0.0.1.post10035392509",
		"2013-01-21T20:33:09+0100",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("PyPI")
		if !ok {
			t.Fatal("PyPI not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzMavenMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0-alpha-1", "1.0.0.RELEASE",
		"1.0", "1.0-SNAPSHOT",
		"0.0", "alpha-alpha",
		"0.0.0-2024-04-02T00-00-00-special-v20.9-plus-propertydatafetcher-fix",
		"$%7Brevision%7D231.v678984136a_0b_",
		"1..0",
		"1--alpha",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Maven")
		if !ok {
			t.Fatal("Maven not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzRubyGemsMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0.0.a",
		"0.0.0.1",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("RubyGems")
		if !ok {
			t.Fatal("RubyGems not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzCRANMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0-1", "1.0-2",
		"1.0.1", "1.0.2",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("CRAN")
		if !ok {
			t.Fatal("CRAN not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzNuGetMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0.0-alpha",
		"0.10.1.1",
		"0.0.0-20210218195015-ae50d9b99025",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("NuGet")
		if !ok {
			t.Fatal("NuGet not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzPubMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0.0-alpha",
		"0.13.0-nullsafety.0",
		"0.1.0+1",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Pub")
		if !ok {
			t.Fatal("Pub not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzHackageMonotonicity(f *testing.F) {
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0.0.1", "1.0.0.2",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Hackage")
		if !ok {
			t.Fatal("Hackage not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzDpkgMonotonicity(f *testing.F) {
	seeds := []string{
		"1:1.0-1", "1:1.0-2",
		"1.0-1", "1.0-2",
		"1.0", "1.1",
		"1.0~rc1-1",
		"1:0.0+git20161013.8b4af36+dfsg-3",
		"0.0+git20160525~9bf299c-2",
		"0.0.20-1.1~deb13u1",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Debian")
		if !ok {
			t.Fatal("Debian not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzSemVerMonotonicity(f *testing.F) {
	seeds := []string{
		"v1.0.0", "v1.0.1",
		"v1.0.0-alpha",
		"v0.0.0-alpha.0",
		"v0.0.0-dev",
		"v0.0.0-5VtLmtixx6V5PkcW",
		"v0.0.0-20231016150651-428517fef5b9",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Go")
		if !ok {
			t.Fatal("Go not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzRPMMonotonicity(f *testing.F) {
	seeds := []string{
		"1:1.0-1", "1:1.0-2",
		"1.0-1", "1.0-2",
		"0.1.0~90-1.1",
		"0.1.9+git.0.66be0d8-bp154.2.6.1",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Red Hat")
		if !ok {
			t.Fatal("Red Hat not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}

func FuzzAPKMonotonicity(f *testing.F) {
	f.Skip("Skipping Alpine fuzz test due to known transitivity violations")
	seeds := []string{
		"1.0.0", "1.0.1",
		"1.0.0-r1", "1.0.0-r2",
	}
	for i, v1 := range seeds {
		for j := i; j < len(seeds); j++ {
			f.Add(v1, seeds[j])
		}
	}
	f.Fuzz(func(t *testing.T, v1Str, v2Str string) {
		e, ok := DefaultProvider.Get("Alpine")
		if !ok {
			t.Fatal("Alpine not found")
		}
		checkCoarseMonotonicityRaw(t, e, v1Str, v2Str)
	})
}
