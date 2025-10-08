package vulns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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

// writeToDisk writes the vulnerability to a local file.
func writeToDisk(v *osvschema.Vulnerability, preModifiedBuf []byte, outputPrefix string) {
	filename := v.ID + ".json"
	filePath := path.Join(outputPrefix, filename)
	err := os.WriteFile(filePath, preModifiedBuf, 0600)
	if err != nil {
		logger.Error("Failed to write OSV file", slog.Any("err", err), slog.String("path", filePath))
	}
}

// uploadToGCS uploads the vulnerability to a GCS bucket.
func uploadToGCS(ctx context.Context, v *osvschema.Vulnerability, preModifiedBuf []byte, outBkt *storage.BucketHandle, outputPrefix string) {
	vulnID := v.ID
	filename := vulnID + ".json"

	hash := sha256.Sum256(preModifiedBuf)
	hexHash := hex.EncodeToString(hash[:])

	objName := path.Join(outputPrefix, filename)
	obj := outBkt.Object(objName)

	// Check if object exists and if hash matches.
	attrs, err := obj.Attrs(ctx)
	if err == nil {
		// Object exists, check hash.
		if attrs.Metadata != nil && attrs.Metadata[hashMetadataKey] == hexHash {
			logger.Info("Skipping upload, hash matches", slog.String("id", vulnID))
			return
		}
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		logger.Error("failed to get object attributes", slog.String("id", vulnID), slog.Any("err", err))
		return
	}

	// Object does not exist or hash differs, upload.
	v.Modified = time.Now().UTC()
	postModifiedBuf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		logger.Error("failed to marshal vulnerability with modified time", slog.String("id", vulnID), slog.Any("err", err))
		return
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

		return
	}

	if err := wc.Close(); err != nil {
		logger.Error("failed to close GCS writer", slog.String("id", vulnID), slog.Any("err", err))
	}
}

// handleOverride checks for and applies a vulnerability override if it exists.
// It returns the vulnerability to process, a pre-marshalled buffer if an override was used,
// and an error if a critical failure occurred.
func handleOverride(ctx context.Context, v *osvschema.Vulnerability, overridesBkt *storage.BucketHandle) (*osvschema.Vulnerability, []byte, error) {
	if overridesBkt == nil {
		return v, nil, nil
	}

	filename := v.ID + ".json"
	overrideObj := overridesBkt.Object(path.Join("osv-output-overrides", filename))
	if _, err := overrideObj.Attrs(ctx); err == nil {
		// Override exists, read it and replace original vulnerability.
		logger.Info("Using override", slog.String("id", v.ID))
		rc, err := overrideObj.NewReader(ctx)
		if err != nil {
			logger.Warn("failed to get reader for override object, using original", slog.String("id", v.ID), slog.Any("err", err))
			return v, nil, nil
		}
		defer rc.Close()

		overrideBuf, err := io.ReadAll(rc)
		if err != nil {
			logger.Warn("failed to read override object, using original", slog.String("id", v.ID), slog.Any("err", err))
			return v, nil, nil
		}

		var overrideV osvschema.Vulnerability
		if err := json.Unmarshal(overrideBuf, &overrideV); err != nil {
			logger.Warn("failed to unmarshal override object, using original", slog.String("id", v.ID), slog.Any("err", err))
			return v, nil, nil
		}

		return &overrideV, overrideBuf, nil
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		logger.Error("failed to check for override object", slog.String("id", v.ID), slog.Any("err", err))
		return nil, nil, err
	}

	// No override found.
	return v, nil, nil
}

// Worker is a generic worker that processes OSV vulnerabilities from a channel.
// It can upload them to a GCS bucket or write them to disk.
// It supports checking for overrides in a separate GCS bucket location if overridesBkt is not nil.
// For GCS uploads, it calculates a hash of the vulnerability (excluding the modified time) and compares it
// with the existing object's hash. The vulnerability is uploaded only if the hashes differ, with the
// modified time updated. This prevents updating the modified time for vulnerabilities with no content changes.
func Worker(ctx context.Context, vulnChan <-chan *osvschema.Vulnerability, outBkt, overridesBkt *storage.BucketHandle, outputPrefix string) {
	for v := range vulnChan {
		vulnID := v.ID
		if len(v.Affected) == 0 {
			logger.Warn("Skipping OSV record as no affected versions found.", slog.String("id", vulnID))
			continue
		}

		vulnToProcess, preModifiedBuf, err := handleOverride(ctx, v, overridesBkt)
		if err != nil {
			continue
		}

		if preModifiedBuf == nil {
			// Marshal before setting modified time to generate hash.
			preModifiedBuf, err = json.MarshalIndent(vulnToProcess, "", "  ")
			if err != nil {
				logger.Error("failed to marshal vulnerability", slog.String("id", vulnID), slog.Any("err", err))
				continue
			}
		}

		if outBkt == nil {
			// Write to local disk
			writeToDisk(vulnToProcess, preModifiedBuf, outputPrefix)
			continue
		}
		// Upload to GCS
		uploadToGCS(ctx, vulnToProcess, preModifiedBuf, outBkt, outputPrefix)
	}
}
