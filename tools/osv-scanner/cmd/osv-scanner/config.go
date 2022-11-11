package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	IgnoredVulns []IgnoreLine
	LoadPath     string
}

type IgnoreLine struct {
	ID          string
	Valid_Until time.Time
	Reason      string
}

// TryLoadConfig tries to load config in `target` (or it's containing directory)
// `target` will be the key for the entry in configMap
// Will shortcut and return "" if configOverride is not nil
func TryLoadConfig(target string) (Config, error) {
	if configOverride != nil {
		return Config{}, errors.New("Global config has been set")
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
	configPath := filepath.Join(containingFolder, osvScannerConfigName)
	configFile, err := os.Open(configPath)
	var config Config
	if err == nil { // File exists, and we have permission to read
		_, err := toml.NewDecoder(configFile).Decode(&config)
		if err != nil {
			log.Fatalf("Failed to read config file: %s\n", err)
		}
		config.LoadPath = configPath
		return config, nil
	}

	return Config{}, fmt.Errorf("No config file found on this path: %s", containingFolder)
}
