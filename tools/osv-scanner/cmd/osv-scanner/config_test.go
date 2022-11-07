package main

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testStruct struct {
	targetPath string
	configPath string
	configErr  error
}

func TestTryLoadConfig(t *testing.T) {
	configMap := map[string]Config{}
	testPaths := []testStruct{
		{
			targetPath: "../../testdata/testdatainner/innerFolder/test.yaml",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
		{
			targetPath: "../../testdata/testdatainner/innerFolder/",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
		{ // Test no slash at the end
			targetPath: "../../testdata/testdatainner/innerFolder",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
		{
			targetPath: "../../testdata/testdatainner/",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
	}

	for _, testPath := range testPaths {
		absPath, err := filepath.Abs(testPath.targetPath)
		if err != nil {
			t.Errorf("%s", err)
		}
		configPath, configErr := TryLoadConfig(absPath, configMap)
		cmp.Equal(configPath, testPath.configPath)
		cmp.Equal(configErr, testPath.configErr)

	}

	for _, elem := range configMap {
		cmp.Equal(elem, Config{
			IgnoredVulns: []IgnoreLine{
				{
					Id: "GO-2022-0968",
				},
				{
					Id: "GO-2022-1059",
				},
			},
		})
	}
}

func TestTryLoadConfigFail(t *testing.T) {
	configMap := map[string]Config{}
	testPaths := []testStruct{
		{
			targetPath: "../../testdata/testdatainner/",
			configPath: "",
			configErr:  LoadConfigError{},
		},
		{
			targetPath: "../../testdata/testdatainner/innerFolder/",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
		{ // Test no slash at the end
			targetPath: "../../testdata/testdatainner/innerFolder",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
		{
			targetPath: "../../testdata/testdatainner/",
			configPath: "../../testdata/testdatainner/osv-scanner.toml",
			configErr:  nil,
		},
	}

	for _, testPath := range testPaths {
		absPath, err := filepath.Abs(testPath.targetPath)
		if err != nil {
			t.Errorf("%s", err)
		}
		configPath, configErr := TryLoadConfig(absPath, configMap)
		cmp.Equal(configPath, testPath.configPath)
		cmp.Equal(configErr, testPath.configErr)

	}

	for _, elem := range configMap {
		cmp.Equal(elem, Config{
			IgnoredVulns: []IgnoreLine{},
		})
	}

}
