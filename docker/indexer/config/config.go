// Package config provides functionality to load configurations
package config

import (
	"context"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/golang/protobuf/proto"

	log "github.com/golang/glog"
	pb "github.com/google/osv.dev/docker/indexer/proto"
)

// Load loads the repository configurations from the provided bucket.
func Load(ctx context.Context, cfgBucket *storage.BucketHandle) ([]*pb.Repository, error) {
	var repos []*pb.Repository
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

		if strings.HasSuffix(attrs.Name, "textproto") {
			obj := cfgBucket.Object(attrs.Name)
			r, err := obj.NewReader(ctx)
			if err != nil {
				log.Errorf("failed to receive object %s: %v", err, attrs.Name)
				continue
			}

			buf, err := io.ReadAll(r)
			if err != nil {
				log.Errorf("failed to read object %s: %v", err, attrs.Name)
				continue
			}

			repo := &pb.Repository{}
			if err := proto.UnmarshalText(string(buf), repo); err != nil {
				log.Errorf("failed to unmarshal repo for object %s: %v", attrs.Name, err)
				continue
			}
			if ok := nameTracker[repo.Name]; ok {
				log.Errorf("duplicated repo name: %s", repo.Name)
				continue
			}
			nameTracker[repo.Name] = true
			repos = append(repos, repo)
			log.Infof("loaded configuration for %s", repo.Name)
		}
	}

	return repos, nil
}
