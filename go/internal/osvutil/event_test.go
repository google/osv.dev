package osvutil

import (
	"errors"
	"testing"

	"github.com/google/osv.dev/go/osv/ecosystem"
)

type mockEcosystem struct {
	parseFunc func(version string) (ecosystem.Version, error)
}

func (m mockEcosystem) Parse(version string) (ecosystem.Version, error) {
	if m.parseFunc != nil {
		return m.parseFunc(version)
	}

	return nil, errors.New("parse error")
}

func (m mockEcosystem) Coarse(_ string) (string, error) {
	return "", nil
}

func (m mockEcosystem) IsSemver() bool {
	return false
}

type mockVersion struct {
	v int
}

func (m mockVersion) Compare(other ecosystem.Version) (int, error) {
	ov, ok := other.(mockVersion)
	if !ok {
		return 0, errors.New("incompatible types")
	}
	if m.v < ov.v {
		return -1, nil
	}
	if m.v > ov.v {
		return 1, nil
	}

	return 0, nil
}

func TestSortEvents_ParseError(t *testing.T) {
	eco := mockEcosystem{
		parseFunc: func(version string) (ecosystem.Version, error) {
			if version == "invalid" {
				return nil, errors.New("invalid version")
			}

			return mockVersion{v: 1}, nil
		},
	}

	events := []Event{
		{Type: Introduced, Version: "1.0"},
		{Type: Fixed, Version: "invalid"},
	}

	err := SortEvents(eco, events)
	if err == nil {
		t.Errorf("Expected error when parsing fails, got nil")
	}

	if err != nil && err.Error() != "invalid version" {
		t.Errorf("Expected error 'invalid version', got '%v'", err)
	}
}

func TestSortEvents_Success(t *testing.T) {
	eco := mockEcosystem{
		parseFunc: func(version string) (ecosystem.Version, error) {
			if version == "1.0" {
				return mockVersion{v: 1}, nil
			}
			if version == "2.0" {
				return mockVersion{v: 2}, nil
			}

			return nil, errors.New("unknown version")
		},
	}

	events := []Event{
		{Type: Fixed, Version: "2.0"},
		{Type: Introduced, Version: "1.0"},
	}

	err := SortEvents(eco, events)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if events[0].Version != "1.0" || events[1].Version != "2.0" {
		t.Errorf("Events not sorted correctly: %v", events)
	}
}
