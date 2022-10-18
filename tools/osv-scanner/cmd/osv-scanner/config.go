package main

import (
	"log"
	"os"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	IgnoredVulnIds []string
}

// TryLoadConfig tries to load config in `target` or any of it's parent dirs
// `target` will be the key for the entry in configMap
// Will shortcut and return "" if globalConfig is not nil
func TryLoadConfig(target string, configMap map[string]Config) string {
	if globalConfig != nil {
		return ""
	}
	stat, err := os.Stat(target)
	if err != nil {
		log.Fatalf("Failed to stat path: %s", err)
	}

	if stat.IsDir() && !strings.HasSuffix(target, "/") {
		// Make sure directories ends with '/'
		target += "/"
	}

	currentDir := target
	for currentDir != "/" {
		currentDir = path.Dir(currentDir)
		fileToRead := path.Join(currentDir, osvScannerConfigName)
		configFile, err := os.Open(fileToRead)
		var config Config
		if err == nil { // File exists, and we have permission to read
			_, err := toml.NewDecoder(configFile).Decode(&config)
			if err != nil {
				log.Fatalf("Failed to read config file: %s\n", err)
			}
			configMap[target] = config
			return fileToRead
		}
	}
	return ""
}
