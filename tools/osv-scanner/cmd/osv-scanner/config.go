package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

type LoadConfigErrorType int64

const (
	GlobalConfigSet LoadConfigErrorType = iota
	NoConfigFound
)

type Config struct {
	IgnoredVulns []IgnoreLine
}

type IgnoreLine struct {
	ID          string
	Valid_Until time.Time
	Reason      string
}

type LoadConfigError struct {
	TargetPath string
	ErrorType  LoadConfigErrorType
}

func (e LoadConfigError) Error() string {
	switch e.ErrorType {
	case GlobalConfigSet:
		return "Global config has been set"
	case NoConfigFound:
		return "No config file found on this or any ancestor path: " + e.TargetPath
	}
	panic("Invalid error type")
}

// TryLoadConfig tries to load config in `target` (or it's containing directory)
// `target` will be the key for the entry in configMap
// Will shortcut and return "" if globalConfig is not nil
func TryLoadConfig(target string, configMap map[string]Config) (string, error) {
	if ignoreOverride != nil {
		return "", LoadConfigError{TargetPath: target, ErrorType: GlobalConfigSet}
	}
	stat, err := os.Stat(target)
	if err != nil {
		log.Fatalf("Failed to stat target: %s", err)
	}

	var containingFolder string
	if !stat.IsDir() {
		containingFolder = filepath.Dir(target)
	} else {
		containingFolder = target
	}

	configFile, err := os.Open(filepath.Join(containingFolder, osvScannerConfigName))
	var config Config
	if err == nil { // File exists, and we have permission to read
		_, err := toml.NewDecoder(configFile).Decode(&config)
		if err != nil {
			log.Fatalf("Failed to read config file: %s\n", err)
		}
		configMap[target] = config
		return containingFolder, nil
	}

	return "", LoadConfigError{TargetPath: target, ErrorType: NoConfigFound}
}
