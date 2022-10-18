package main

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTryLoadConfig(t *testing.T) {
	configMap := map[string]Config{}
	testPaths := []string{
		"../../testdata/innerFolder/test.yaml",
		"../../testdata/innerFolder/",
		"../../testdata/",
	}

	for _, path := range testPaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			t.Errorf("%s", err)
		}
		TryLoadConfig(absPath, configMap)
	}

	for _, elem := range configMap {
		cmp.Equal(elem, Config{
			IgnoredVulnIds: []string{
				"GO-2022-0968",
				"GO-2022-1059",
			},
		})
	}

}
