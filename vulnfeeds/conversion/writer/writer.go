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

// prepareVulnUpload marshals a vulnerability record, calculates its SHA256 hash (excluding the Modified time), updates its Modified time, and returns the hash and the updated payload.
func prepareVulnUpload(vuln *osvschema.Vulnerability) (hexHash string, postModifiedBuf []byte, err error) {
	if vuln == nil || vuln.GetId() == "" {
		return "", nil, errors.New("invalid vulnerability provided")
	}

	var buf bytes.Buffer
	v := vulns.Vulnerability{Vulnerability: vuln}
	if err := v.ToJSON(&buf); err != nil {
		return "", nil, fmt.Errorf("failed to marshal vulnerability %s: %w", vuln.GetId(), err)
	}
	preModifiedBuf := buf.Bytes()
	hash := sha256.Sum256(preModifiedBuf)
	hexHash = hex.EncodeToString(hash[:])

	vuln.Modified = timestamppb.New(time.Now().UTC())
	var postBuf bytes.Buffer
	vPost := vulns.Vulnerability{Vulnerability: vuln}
	if err := vPost.ToJSON(&postBuf); err != nil {
		return "", nil, fmt.Errorf("failed to marshal vulnerability with modified time for %s: %w", vuln.GetId(), err)
	}

	return hexHash, postBuf.Bytes(), nil
}

// uploadIfChanged uploads the vulnerability to a GCS bucket if it has changed.
// It returns an error if the upload failed, or ErrUploadSkipped if the upload
// was intentionally avoided (e.g. because the GCS object has a matching hash).
func uploadIfChanged(ctx context.Context, v *osvschema.Vulnerability, hexHash string, postModifiedBuf []byte, outBkt *storage.BucketHandle, outputPrefix string) error {
	vulnID := v.GetId()
	filename := vulnID + ".json"

	objName := path.Join(outputPrefix, filename)
	obj := outBkt.Object(objName)

	// Check if object exists and if hash matches.
	attrs, err := obj.Attrs(ctx)
	if err == nil {
		// Object exists, check hash.
		if attrs.Metadata != nil && attrs.Metadata[hashMetadataKey] == hexHash {
			logger.Info("Skipping GCS upload, hash matches", slog.String("id", vulnID), slog.String("object", objName))
			return ErrUploadSkipped
		}
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("failed to get object attributes for %s: %w", vulnID, err)
	}

	// Object does not exist or hash differs, upload.
	logger.Info("Uploading vulnerability record to GCS", slog.String("id", vulnID), slog.String("object", objName))

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

// VulnWorker is a generic worker that processes OSV vulnerabilities from a channel.
// It can upload them to a GCS bucket or write them to disk.
// It supports checking for overrides in a separate GCS bucket location if overridesBkt is not nil.
// For GCS uploads, it calculates a hash of the vulnerability (excluding the modified time) and compares it
// with the existing object's hash. The vulnerability is uploaded only if the hashes differ, with the
// modified time updated. This prevents updating the modified time for vulnerabilities with no content changes.
func VulnWorker(ctx context.Context, vulnChan <-chan *osvschema.Vulnerability, outBkt, overridesBkt *storage.BucketHandle, gcsHelper *gcs.Helper, outputPrefix string, counter *atomic.Uint64) {
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

		var writeErr error
		if outBkt == nil && gcsHelper == nil {
			// Write to local disk
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
			writeErr = writeToDisk(vulnToProcess, preModifiedBuf, outputPrefix)
		} else if gcsHelper != nil {
			// Upload to GCS asynchronously using pool
			writeErr = UploadVulnIfChangedAsync(gcsHelper, outputPrefix, vulnToProcess)
		} else {
			// Upload to GCS synchronously
			hexHash, postModifiedBuf, err := prepareVulnUpload(vulnToProcess)
			if err != nil {
				writeErr = err
			} else {
				writeErr = uploadIfChanged(ctx, vulnToProcess, hexHash, postModifiedBuf, outBkt, outputPrefix)
			}
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
	var gcsHelper *gcs.Helper
	if uploadToGCS {
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			logger.Fatal("Failed to create storage client", slog.Any("err", err))
		}
		defer storageClient.Close()

		outBkt = storageClient.Bucket(outputBucketName)
		if overridesBucketName != "" {
			overridesBkt = storageClient.Bucket(overridesBucketName)
		}

		if doDeletions {
			HandleDeletion(ctx, outBkt, osvOutputPath, vulnerabilities)
		}

		gcsHelper, err = gcs.InitUploadPool(ctx, numWorkers, outputBucketName)
		if err != nil {
			logger.Fatal("Failed to initialize GCS upload pool", slog.Any("err", err))
		}
		defer gcsHelper.CloseAndWait()
	}
	var wg sync.WaitGroup
	var successCount atomic.Uint64
	vulnChan := make(chan *osvschema.Vulnerability, numWorkers)

	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			VulnWorker(ctx, vulnChan, outBkt, overridesBkt, gcsHelper, osvOutputPath, &successCount)
		}()
	}

	for _, v := range vulnerabilities {
		vulnChan <- v
	}

	close(vulnChan)
	wg.Wait()
	if gcsHelper != nil {
		gcsHelper.CloseAndWait()
	}
	logger.Info("Successfully processed "+jobName, slog.Int("count", len(vulnerabilities)))
	if outBkt == nil && gcsHelper == nil {
		logger.Info("Successfully wrote records to disk", slog.Uint64("count", successCount.Load()))
	}
}

func HandleDeletion(ctx context.Context, outBkt *storage.BucketHandle, osvOutputPath string, vulnerabilities []*osvschema.Vulnerability) {
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

// UploadVulnToGCS marshals a single OSV Vulnerability to JSON and unconditionally uploads it to GCS.
func UploadVulnToGCS(ctx context.Context, bkt *storage.BucketHandle, prefix string, vuln *osvschema.Vulnerability) error {
	if vuln == nil || vuln.GetId() == "" {
		return errors.New("invalid vulnerability provided")
	}

	data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(vuln)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability %s: %w", vuln.GetId(), err)
	}

	objectName := path.Join(prefix, vuln.GetId()+".json")
	logger.Info("Uploading vulnerability record to GCS", slog.String("id", vuln.GetId()), slog.String("object", objectName))
	reader := bytes.NewReader(data)

	return gcs.UploadToGCS(ctx, bkt, objectName, reader, "application/json", nil)
}

// UploadVulnIfChanged marshals a single OSV Vulnerability to JSON and uploads it to GCS if it has changed.
func UploadVulnIfChanged(ctx context.Context, bkt *storage.BucketHandle, prefix string, vuln *osvschema.Vulnerability) error {
	hexHash, postModifiedBuf, err := prepareVulnUpload(vuln)
	if err != nil {
		return err
	}

	err = uploadIfChanged(ctx, vuln, hexHash, postModifiedBuf, bkt, prefix)
	if errors.Is(err, ErrUploadSkipped) {
		return nil
	}

	return err
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

	objectName := path.Join(prefix, string(cveID)+".metrics.json")
	logger.Debug("Uploading conversion metrics record to GCS", slog.String("id", string(cveID)), slog.String("object", objectName))
	reader := bytes.NewReader(data)

	return gcs.UploadToGCS(ctx, bkt, objectName, reader, "application/json", nil)
}

// UploadVulnIfChangedAsync marshals a single OSV Vulnerability to JSON and schedules it for upload via the Helper pool if it has changed.
func UploadVulnIfChangedAsync(gcsHelper *gcs.Helper, prefix string, vuln *osvschema.Vulnerability) error {
	hexHash, postModifiedBuf, err := prepareVulnUpload(vuln)
	if err != nil {
		return err
	}

	objectName := path.Join(prefix, vuln.GetId()+".json")
	gcsHelper.Upload(objectName, bytes.NewReader(postModifiedBuf), hexHash, "application/json")

	return nil
}

// UploadMetricsToGCSAsync marshals ConversionMetrics to JSON and schedules it for upload via the Helper pool.
func UploadMetricsToGCSAsync(gcsHelper *gcs.Helper, prefix string, cveID models.CVEID, metrics *models.ConversionMetrics) error {
	if metrics == nil || cveID == "" {
		return errors.New("invalid metrics or CVE ID provided")
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics for %s: %w", cveID, err)
	}

	objectName := path.Join(prefix, string(cveID)+".metrics.json")
	reader := bytes.NewReader(data)

	gcsHelper.Upload(objectName, reader, "", "application/json")

	return nil
}

// CreateMetricsFile creates the initial file for the metrics record.
func CreateMetricsFile(id models.CVEID, vulnDir string) (*os.File, error) {
	metricsFile := path.Join(vulnDir, string(id)+".metrics"+models.Extension)
	f, err := os.Create(metricsFile)
	if err != nil {
		logger.Info("Failed to open for writing "+metricsFile, slog.String("cve", string(id)), slog.String("path", metricsFile), slog.Any("err", err))
		return nil, err
	}

	return f, nil
}

// CreateOSVFile creates the initial file for the OSV record.
func CreateOSVFile(id models.CVEID, vulnDir string) (*os.File, error) {
	outputFile := path.Join(vulnDir, string(id)+models.Extension)

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
