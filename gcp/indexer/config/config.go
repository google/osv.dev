/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Package config provides functionality to load configurations
package config

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"gopkg.in/yaml.v3"

	log "github.com/golang/glog"
)

// RepoConfig holds the configuration for a single repository.
type RepoConfig struct {
	Address          string   `yaml:"address"`
	Name             string   `yaml:"name"`
	Type             string   `yaml:"type"`
	BaseCPE          string   `yaml:"base_cpe"`
	BranchVersioning bool     `yaml:"branch_versioning,omitempty"`
	HashAllCommits   bool     `yaml:"hash_all_commits,omitempty"`
	FileExts         []string `yaml:"file_extensions"`
}

// Load loads the repository configurations from the provided bucket.
func Load(ctx context.Context, cfgBucket *storage.BucketHandle) ([]*RepoConfig, error) {
	var repos []*RepoConfig
	nameTracker := make(map[string]bool)
	iter := cfgBucket.Objects(ctx, nil)
	for {
		attrs, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Ext(attrs.Name) != ".yaml" {
			continue
		}

		obj := cfgBucket.Object(attrs.Name)
		r, err := obj.NewReader(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to receive object %s: %v", err, attrs.Name)
		}

		buf, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read object %s: %v", err, attrs.Name)
		}
		cfg, err := parseConfig(buf)
		if err != nil {
			log.Errorf("failed to parse config: %s", err)
			continue
		}

		if nameTracker[cfg.Name] {
			log.Errorf("duplicated configuration name %s", cfg.Name)
			continue
		}
		nameTracker[cfg.Name] = true
		cfg.Type = strings.ToUpper(cfg.Type)
		repos = append(repos, cfg)
	}

	return repos, nil
}

func parseConfig(buf []byte) (*RepoConfig, error) {
	cfg := &RepoConfig{}
	if err := yaml.Unmarshal(buf, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
