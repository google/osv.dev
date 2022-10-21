package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type LoadConfigErrorType int64

const (
	GlobalConfigSet LoadConfigErrorType = iota
	NoConfigFound
)

type Config struct {
	IgnoredVulnIds []string
}

type LoadConfigError struct {
	targetPath string
	errorType  LoadConfigErrorType
}

func (e LoadConfigError) Error() string {
	switch e.errorType {
	case GlobalConfigSet:
		return "Global config has been set"
	case NoConfigFound:
		return "No config file found on this or any ancestor path: " + e.targetPath
	}
	panic("Invalid error type")
}

// TryLoadConfig tries to load config in `target` or any of it's parent dirs
// `target` will be the key for the entry in configMap
// Will shortcut and return "" if globalConfig is not nil
func TryLoadConfig(target string, configMap map[string]Config) (string, error) {
	if globalConfig != nil {
		return "", LoadConfigError{targetPath: target, errorType: GlobalConfigSet}
	}
	stat, err := os.Stat(target)
	if err != nil {
		log.Fatalf("Failed to stat target: %s", err)
	}

	if stat.IsDir() && !strings.HasSuffix(target, string(filepath.Separator)) {
		// Make sure directories ends with '/'
		target += string(filepath.Separator)
	}

	currentDir := target
	for currentDir != "/" {
		currentDir = filepath.Dir(currentDir)
		fileToRead := filepath.Join(currentDir, osvScannerConfigName)
		configFile, err := os.Open(fileToRead)
		var config Config
		if err == nil { // File exists, and we have permission to read
			_, err := toml.NewDecoder(configFile).Decode(&config)
			if err != nil {
				log.Fatalf("Failed to read config file: %s\n", err)
			}
			configMap[target] = config
			return fileToRead, nil
		}
	}
	return "", LoadConfigError{targetPath: target, errorType: NoConfigFound}
}
