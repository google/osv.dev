package triage

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type falsePositives struct {
	IDs      []string `yaml:"ids"`
	Packages []string `yaml:"packages"`
}

type FalsePositives struct {
	IDs      map[string]bool
	Packages map[string]bool
}

func LoadFalsePositives(path string) (*FalsePositives, error) {
	result := FalsePositives{
		IDs:      map[string]bool{},
		Packages: map[string]bool{},
	}

	if path == "" {
		// Empty false positives.
		return &result, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	var data falsePositives
	err = decoder.Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	for _, id := range data.IDs {
		result.IDs[id] = true
	}

	for _, pkg := range data.Packages {
		result.Packages[pkg] = true
	}

	return &result, nil
}

func (f *FalsePositives) CheckID(id string) bool {
	return f.IDs[id]
}

func (f *FalsePositives) CheckPackage(pkg string) bool {
	return f.Packages[pkg]
}
