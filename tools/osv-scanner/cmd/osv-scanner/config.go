package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/exp/slices"
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

func (c *Config) ShouldIgnore(vulnID string) (bool, IgnoreLine) {
	index := slices.IndexFunc(c.IgnoredVulns, func(elem IgnoreLine) bool { return elem.ID == vulnID })
	if index == -1 {
		return false, IgnoreLine{}
	}
	return true, c.IgnoredVulns[index]
}

// TryLoadConfig tries to load config in `target` (or it's containing directory)
// `target` will be the key for the entry in configMap
func TryLoadConfig(target string) (Config, error) {
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
