package vulns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/utility/logger"
)

const (
	// HashMetadataKey is the key for the sha256 hash in the GCS object metadata.
	HashMetadataKey = "sha256-hash"
)

// Worker is a generic worker that processes vulnerabilities from a channel and uploads them to a GCS bucket.
func Worker(ctx context.Context, vulnChan <-chan *Vulnerability, bkt *storage.BucketHandle, outputDir string) {
	for v := range vulnChan {
		vulnID := v.ID
		if len(v.Affected) == 0 {
			logger.Warn(fmt.Sprintf("Skipping %s as no affected versions found.", vulnID), slog.String("id", vulnID))
			continue
		}

		// Marshal before setting modified time to generate hash.
		buf, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			logger.Error("failed to marshal vulnerability", slog.String("id", vulnID), slog.Any("err", err))
			continue
		}

		hash := sha256.Sum256(buf)
		hexHash := hex.EncodeToString(hash[:])

		objName := path.Join(outputDir, vulnID+".json")
		obj := bkt.Object(objName)

		// Check if object exists and if hash matches.
		attrs, err := obj.Attrs(ctx)
		if err == nil {
			// Object exists, check hash.
			if attrs.Metadata != nil && attrs.Metadata[HashMetadataKey] == hexHash {
				logger.Info("Skipping upload, hash matches", slog.String("id", vulnID))
				continue
			}
		} else if !errors.Is(err, storage.ErrObjectNotExist) {
			logger.Error("failed to get object attributes", slog.String("id", vulnID), slog.Any("err", err))
			continue
		}

		// Object does not exist or hash differs, upload.
		v.Modified = time.Now().UTC()
		buf, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			logger.Error("failed to marshal vulnerability with modified time", slog.String("id", vulnID), slog.Any("err", err))
			continue
		}

		logger.Info("Uploading", slog.String("id", vulnID))
		wc := obj.NewWriter(ctx)
		wc.Metadata = map[string]string{
			HashMetadataKey: hexHash,
		}
		wc.ContentType = "application/json"

		if _, err := wc.Write(buf); err != nil {
			logger.Error("failed to write to GCS object", slog.String("id", vulnID), slog.Any("err", err))
			// Try to close writer even if write failed.
			if closeErr := wc.Close(); closeErr != nil {
				logger.Error("failed to close GCS writer after write error", slog.String("id", vulnID), slog.Any("err", closeErr))
			}

			continue
		}

		if err := wc.Close(); err != nil {
			logger.Error("failed to close GCS writer", slog.String("id", vulnID), slog.Any("err", err))
			continue
		}
	}
}
