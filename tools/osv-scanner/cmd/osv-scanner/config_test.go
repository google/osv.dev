package main

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testStruct struct {
	targetPath   string
	config       Config
	configHasErr bool
}

func TestTryLoadConfig(t *testing.T) {

	expectedConfig := Config{
		IgnoredVulns: []IgnoreLine{
			{
				ID: "GO-2022-0968",
			},
			{
				ID: "GO-2022-1059",
			},
		},
	}
	testPaths := []testStruct{
		{
			targetPath:   "../../testdata/testdatainner/innerFolder/test.yaml",
			config:       expectedConfig,
			configHasErr: true,
		},
		{
			targetPath:   "../../testdata/testdatainner/innerFolder/",
			config:       Config{},
			configHasErr: true,
		},
		{ // Test no slash at the end
			targetPath:   "../../testdata/testdatainner/innerFolder",
			config:       Config{},
			configHasErr: true,
		},
		{
			targetPath:   "../../testdata/testdatainner/",
			config:       expectedConfig,
			configHasErr: false,
		},
		{
			targetPath:   "../../testdata/testdatainner/some-manifest.yaml",
			config:       expectedConfig,
			configHasErr: false,
		},
	}

	for _, testData := range testPaths {
		absPath, err := filepath.Abs(testData.targetPath)
		if err != nil {
			t.Errorf("%s", err)
		}
		config, configErr := TryLoadConfig(absPath)
		cmp.Equal(config, testData.config)
		if testData.configHasErr {
			cmp.Equal(configErr, nil)
		}
	}
}
