package ecosystem

import (
	"testing"
)

type rootTestCase struct {
	v1  string
	v2  string
	cmp int
}

func runRootTest(t *testing.T, e Ecosystem, tests []rootTestCase) {
	t.Helper()

	for _, tc := range tests {
		v1, err := e.Parse(tc.v1)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", tc.v1, err)
		}
		v2, err := e.Parse(tc.v2)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", tc.v2, err)
		}

		c, err := v1.Compare(v2)
		if err != nil {
			t.Fatalf("Compare(%q, %q) error: %v", tc.v1, tc.v2, err)
		}

		if c != tc.cmp {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.v1, tc.v2, c, tc.cmp)
		}
	}
}

func TestRootEcosystem_Alpine(t *testing.T) {
	e := rootEcosystemFactory("Root:Alpine:3.18")
	tests := []rootTestCase{
		{"1.51.0-r20072", "1.51.0-r20071", 1},
		{"1.0.0-r2", "1.0.0-r1", 1},
		{"0", "1.0.0-r1", -1},
		{"1.51.0-r20071", "1.51.0-r20071", 0},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_Debian(t *testing.T) {
	e := rootEcosystemFactory("Root:Debian:12")
	tests := []rootTestCase{
		{"22.12.0-2+deb12u1.root.io.5", "22.12.0-2.root.io.1", 1},
		{"1.18.0-6+deb11u3-r20072", "1.18.0-6+deb11u3-r20071", 1},
		{"1.18.0-6+deb11u3-r20071", "1.18.0-6+deb11u3-r20071", 0},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_Ubuntu(t *testing.T) {
	e := rootEcosystemFactory("Root:Ubuntu:22.04")
	tests := []rootTestCase{
		{"1.2.3-4ubuntu2", "1.2.3-4ubuntu1", 1},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_PyPI(t *testing.T) {
	e := rootEcosystemFactory("Root:PyPI")
	tests := []rootTestCase{
		{"1.0.0+root.io.5", "1.0.0+root.io.1", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0rc1", 1},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_NPM(t *testing.T) {
	e := rootEcosystemFactory("Root:npm")
	tests := []rootTestCase{
		{"1.0.0.root.io.5", "1.0.0.root.io.1", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.1", "1.0.0", 1},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_Maven(t *testing.T) {
	e := rootEcosystemFactory("Root:Maven")
	tests := []rootTestCase{
		{"2.0", "1.0", 1},
		{"1.0", "1.0-SNAPSHOT", 1},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_Unknown(t *testing.T) {
	e := rootEcosystemFactory("Root")
	tests := []rootTestCase{
		{"1.0.0-r2", "1.0.0-r1", 1},
		{"2.0.0", "1.0.0", 1},
	}
	runRootTest(t, e, tests)
}

func TestRootEcosystem_Issue4396(t *testing.T) {
	e := rootEcosystemFactory("Root:Debian:12")
	tests := []rootTestCase{
		{"22.12.0-2.root.io.1", "22.12.0-2+deb12u1.root.io.5", -1},
	}
	runRootTest(t, e, tests)
}
