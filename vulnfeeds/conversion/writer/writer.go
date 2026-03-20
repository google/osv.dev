// Package writer handles allocating workers to intelligently uploading OSV records to a bucket
package writer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/osv/vulnfeeds/gcs-tools"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	// hashMetadataKey is the key for the sha256 hash in the GCS object metadata.
	hashMetadataKey = "sha256-hash"
	overrideFolder  = "osv-output-overrides" // location of overrides within bucket
)

// ErrUploadSkipped indicates that an upload was intentionally skipped because
// the vulnerability payload is unchanged.
var ErrUploadSkipped = errors.New("upload skipped")

// writeToDisk writes the vulnerability to a local file.
// It returns an error if the file could not be written.
func writeToDisk(v *osvschema.Vulnerability, preModifiedBuf []byte, outputPrefix string) error {
	filename := v.GetId() + ".json"
	filePath := path.Join(outputPrefix, filename)
	err := os.WriteFile(filePath, preModifiedBuf, 0600)
	if err != nil {
		return fmt.Errorf("failed to write OSV file at %s: %w", filePath, err)
	}

	return nil
}

// uploadIfChanged uploads the vulnerability to a GCS bucket.
// It returns an error if the upload failed, or ErrUploadSkipped if the upload
// was intentionally avoided (e.g. because the GCS object has a matching hash).
func uploadIfChanged(ctx context.Context, v *osvschema.Vulnerability, preModifiedBuf []byte, outBkt *storage.BucketHandle, outputPrefix string) error {
	vulnID := v.GetId()
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
			return ErrUploadSkipped
		}
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("failed to get object attributes for %s: %w", vulnID, err)
	}

	// Object does not exist or hash differs, upload.
	v.Modified = timestamppb.New(time.Now().UTC())
	vuln := vulns.Vulnerability{Vulnerability: v}
	var buf bytes.Buffer
	if err := vuln.ToJSON(&buf); err != nil {
		return fmt.Errorf("failed to marshal vulnerability with modified time for %s: %w", vulnID, err)
	}
	postModifiedBuf := buf.Bytes()

	wc := obj.NewWriter(ctx)
	wc.Metadata = map[string]string{
		hashMetadataKey: hexHash,
	}
	wc.ContentType = "application/json"

	if _, err := wc.Write(postModifiedBuf); err != nil {
		// Try to close writer even if write failed.
		if closeErr := wc.Close(); closeErr != nil {
			logger.Error("failed to close GCS writer after write error", slog.String("id", vulnID), slog.Any("err", closeErr))
		}

		return fmt.Errorf("failed to write to GCS object for %s: %w", vulnID, err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close GCS writer for %s: %w", vulnID, err)
	}

	return nil
}

// handleOverride checks for and applies a vulnerability override if it exists.
// It returns the vulnerability to process, a pre-marshalled buffer if an override was used,
// and an error if a critical failure occurred.
func handleOverride(ctx context.Context, v *osvschema.Vulnerability, overridesBkt *storage.BucketHandle) (*osvschema.Vulnerability, []byte, error) {
	filename := v.GetId() + ".json"
	overrideObj := overridesBkt.Object(path.Join(overrideFolder, filename))
	if _, err := overrideObj.Attrs(ctx); err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			// No override found.
			return v, nil, nil
		}
		// For any other error, we can't know if an override exists, so we return an error.
		logger.Error("failed to check for override object", slog.String("id", v.GetId()), slog.Any("err", err))

		return nil, nil, err
	}

	// Override exists, read it and replace original vulnerability.
	logger.Info("Using override", slog.String("id", v.GetId()))
	rc, err := overrideObj.NewReader(ctx)
	if err != nil {
		logger.Error("failed to get reader for override object", slog.String("id", v.GetId()), slog.Any("err", err))
		return nil, nil, err
	}
	defer rc.Close()

	overrideBuf, err := io.ReadAll(rc)
	if err != nil {
		logger.Error("failed to read override object", slog.String("id", v.GetId()), slog.Any("err", err))
		return nil, nil, err
	}

	var overrideV osvschema.Vulnerability
	if err := protojson.Unmarshal(overrideBuf, &overrideV); err != nil {
		logger.Error("failed to unmarshal override object", slog.String("id", v.GetId()), slog.Any("err", err))
		return nil, nil, err
	}

	return &overrideV, overrideBuf, nil
}

// Worker is a generic worker that processes OSV vulnerabilities from a channel.
// It can upload them to a GCS bucket or write them to disk.
// It supports checking for overrides in a separate GCS bucket location if overridesBkt is not nil.
// For GCS uploads, it calculates a hash of the vulnerability (excluding the modified time) and compares it
// with the existing object's hash. The vulnerability is uploaded only if the hashes differ, with the
// modified time updated. This prevents updating the modified time for vulnerabilities with no content changes.
func VulnWorker(ctx context.Context, vulnChan <-chan *osvschema.Vulnerability, outBkt, overridesBkt *storage.BucketHandle, outputPrefix string, counter *atomic.Uint64) {
	for v := range vulnChan {
		vulnID := v.GetId()
		if len(v.GetAffected()) == 0 {
			logger.Warn("Skipping OSV record as no affected versions found.", slog.String("id", vulnID))
			continue
		}
		vulnToProcess := v
		var preModifiedBuf []byte
		var err error

		if overridesBkt != nil {
			vulnToProcess, preModifiedBuf, err = handleOverride(ctx, v, overridesBkt)
			if err != nil {
				logger.Error("Failed to use override", slog.Any("error", err))
				continue
			}
		}

		if preModifiedBuf == nil {
			// Marshal before setting modified time to generate hash.
			vuln := vulns.Vulnerability{Vulnerability: v}
			var buf bytes.Buffer
			if err := vuln.ToJSON(&buf); err != nil {
				logger.Error("failed to marshal vulnerability", slog.String("id", vulnID), slog.Any("err", err))
				continue
			}
			preModifiedBuf = buf.Bytes()
		}

		var writeErr error
		if outBkt == nil {
			// Write to local disk
			writeErr = writeToDisk(vulnToProcess, preModifiedBuf, outputPrefix)
		} else {
			// Upload to GCS
			writeErr = uploadIfChanged(ctx, vulnToProcess, preModifiedBuf, outBkt, outputPrefix)
		}

		if writeErr == nil {
			logger.Info("Uploaded successfully", slog.String("id", vulnID))
			if counter != nil {
				counter.Add(1)
			}
		} else if errors.Is(writeErr, ErrUploadSkipped) {
			logger.Info("Skipping upload, hash matches", slog.String("id", vulnID))
		} else {
			logger.Error("Failed to upload/write", slog.String("id", vulnID), slog.Any("err", writeErr))
		}
	}
}

// UploadVulnsToGCS delegates workers to upload vulnerabilities to the buckets.
func UploadVulnsToGCS(
	ctx context.Context,
	jobName string,
	uploadToGCS bool,
	outputBucketName string,
	overridesBucketName string,
	numWorkers int,
	osvOutputPath string,
	vulnerabilities []*osvschema.Vulnerability,
	doDeletions bool,
) {
	var outBkt, overridesBkt *storage.BucketHandle
	if uploadToGCS {
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			logger.Fatal("Failed to create storage client", slog.Any("err", err))
		}
		outBkt = storageClient.Bucket(outputBucketName)
		if overridesBucketName != "" {
			overridesBkt = storageClient.Bucket(overridesBucketName)
		}

		if doDeletions {
			handleDeletion(ctx, outBkt, osvOutputPath, vulnerabilities)
		}
	}
	var wg sync.WaitGroup
	var successCount atomic.Uint64
	vulnChan := make(chan *osvschema.Vulnerability, numWorkers)

	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			VulnWorker(ctx, vulnChan, outBkt, overridesBkt, osvOutputPath, &successCount)
		}()
	}

	for _, v := range vulnerabilities {
		vulnChan <- v
	}

	close(vulnChan)
	wg.Wait()
	logger.Info("Successfully processed "+jobName, slog.Int("count", len(vulnerabilities)))
	logger.Info("Successfully uploaded records", slog.Uint64("count", successCount.Load()))
}

func handleDeletion(ctx context.Context, outBkt *storage.BucketHandle, osvOutputPath string, vulnerabilities []*osvschema.Vulnerability) {
	// Check if any need to be deleted
	bucketObjects, err := gcs.ListBucketObjects(ctx, outBkt, osvOutputPath)
	if err != nil {
		logger.Error("Failed to list bucket objects for deletion check, skipping deletion.", slog.Any("err", err))
		return
	}
	vulnFilenames := make(map[string]bool)
	for _, v := range vulnerabilities {
		filename := v.GetId() + ".json"
		filePath := path.Join(osvOutputPath, filename)
		vulnFilenames[filePath] = true
	}
	for _, objName := range bucketObjects {
		if !vulnFilenames[objName] {
			logger.Info("Deleting stale object from bucket", slog.String("name", objName))
			obj := outBkt.Object(objName)
			if err := obj.Delete(ctx); err != nil {
				logger.Error("Failed to delete object", slog.String("name", objName), slog.Any("err", err))
			}
		}
	}
}

// UploadVulnToGCS marshals a single OSV Vulnerability to JSON and uploads it to GCS.
func UploadVulnToGCS(ctx context.Context, bkt *storage.BucketHandle, prefix string, vuln *osvschema.Vulnerability) error {
	if vuln == nil || vuln.GetId() == "" {
		return errors.New("invalid vulnerability provided")
	}

	data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(vuln)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability %s: %w", vuln.GetId(), err)
	}

	objectName := filepath.Join(prefix, vuln.GetId()+".json")
	reader := bytes.NewReader(data)

	return gcs.UploadToGCS(ctx, bkt, objectName, reader, "application/json")
}

// UploadMetricsToGCS marshals ConversionMetrics to JSON and uploads it to GCS.
func UploadMetricsToGCS(ctx context.Context, bkt *storage.BucketHandle, prefix string, cveID models.CVEID, metrics *models.ConversionMetrics) error {
	if metrics == nil || cveID == "" {
		return errors.New("invalid metrics or CVE ID provided")
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics for %s: %w", cveID, err)
	}

	objectName := filepath.Join(prefix, string(cveID)+".metrics.json")
	reader := bytes.NewReader(data)

	return gcs.UploadToGCS(ctx, bkt, objectName, reader, "application/json")
}

// CreateMetricsFile creates the initial file for the metrics record.
func CreateMetricsFile(id models.CVEID, vulnDir string) (*os.File, error) {
	metricsFile := filepath.Join(vulnDir, string(id)+".metrics"+models.Extension)
	f, err := os.Create(metricsFile)
	if err != nil {
		logger.Info("Failed to open for writing "+metricsFile, slog.String("cve", string(id)), slog.String("path", metricsFile), slog.Any("err", err))
		return nil, err
	}

	return f, nil
}

// CreateOSVFile creates the initial file for the OSV record.
func CreateOSVFile(id models.CVEID, vulnDir string) (*os.File, error) {
	outputFile := filepath.Join(vulnDir, string(id)+models.Extension)

	f, err := os.Create(outputFile)
	if err != nil {
		logger.Info("Failed to open for writing "+outputFile, slog.String("cve", string(id)), slog.String("path", outputFile), slog.Any("err", err))
		return nil, err
	}

	return f, err
}

func WriteMetricsFile(metrics *models.ConversionMetrics, metricsFile *os.File) error {
	marshalledMetrics, err := json.MarshalIndent(&metrics, "", "  ")
	if err != nil {
		logger.Info("Failed to marshal", slog.Any("err", err))
		return err
	}

	_, err = metricsFile.Write(marshalledMetrics)
	if err != nil {
		logger.Warn("Failed to write", slog.String("path", metricsFile.Name()), slog.Any("err", err))
		return fmt.Errorf("failed to write %s: %w", metricsFile.Name(), err)
	}

	metricsFile.Close()

	return nil
}
