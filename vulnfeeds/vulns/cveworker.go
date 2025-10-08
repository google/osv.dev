package vulns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	// hashMetadataKey is the key for the sha256 hash in the GCS object metadata.
	hashMetadataKey = "sha256-hash"
)

// Worker is a generic worker that processes OSV vulnerabilities from a channel.
// It can upload them to a GCS bucket or write them to disk.
// It supports checking for overrides in a separate GCS bucket location if overridesBkt is not nil.
func Worker(ctx context.Context, vulnChan <-chan *osvschema.Vulnerability, outBkt, overridesBkt *storage.BucketHandle, outputPrefix string) {
	for v := range vulnChan {
		vulnID := v.ID
		if len(v.Affected) == 0 {
			logger.Warn("Skipping OSV record as no affected versions found.", slog.String("id", vulnID))
			continue
		}

		// Marshal before setting modified time to generate hash.
		preModifiedBuf, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			logger.Error("failed to marshal vulnerability", slog.String("id", vulnID), slog.Any("err", err))
			continue
		}

		hash := sha256.Sum256(preModifiedBuf)
		hexHash := hex.EncodeToString(hash[:])
		filename := vulnID + ".json"

		if outBkt != nil {
			// Upload to GCS
			if overridesBkt != nil {
				overrideObj := overridesBkt.Object(path.Join("osv-output-overrides", filename))
				if _, err := overrideObj.Attrs(ctx); err == nil {
					logger.Info("Skipping upload, override exists", slog.String("id", v.ID))
					continue
				}
			}

			objName := path.Join(outputPrefix, filename)
			obj := outBkt.Object(objName)

			// Check if object exists and if hash matches.
			attrs, err := obj.Attrs(ctx)
			if err == nil {
				// Object exists, check hash.
				if attrs.Metadata != nil && attrs.Metadata[hashMetadataKey] == hexHash {
					logger.Info("Skipping upload, hash matches", slog.String("id", vulnID))
					continue
				}
			} else if !errors.Is(err, storage.ErrObjectNotExist) {
				logger.Error("failed to get object attributes", slog.String("id", vulnID), slog.Any("err", err))
				continue
			}

			// Object does not exist or hash differs, upload.
			v.Modified = time.Now().UTC()
			postModifiedBuf, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				logger.Error("failed to marshal vulnerability with modified time", slog.String("id", vulnID), slog.Any("err", err))
				continue
			}

			logger.Info("Uploading", slog.String("id", vulnID))
			wc := obj.NewWriter(ctx)
			wc.Metadata = map[string]string{
				hashMetadataKey: hexHash,
			}
			wc.ContentType = "application/json"

			if _, err := wc.Write(postModifiedBuf); err != nil {
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
		} else {
			// Write to local disk
			filePath := path.Join(outputPrefix, filename)
			err := os.WriteFile(filePath, preModifiedBuf, 0600)
			if err != nil {
				logger.Error("Failed to write OSV file", slog.Any("err", err), slog.String("path", filePath))
			}
		}
	}
}
