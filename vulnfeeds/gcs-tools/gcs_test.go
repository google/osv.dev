package gcs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fsouza/fake-gcs-server/fakestorage"
)

func TestUploadToGCS(t *testing.T) {
	server := fakestorage.NewServer([]fakestorage.Object{})
	t.Cleanup(server.Stop)

	client := server.Client()
	bkt := client.Bucket("test-bucket")
	if err := bkt.Create(context.Background(), "project", nil); err != nil {
		t.Fatalf("failed to create bucket: %v", err)
	}

	content := []byte("test content")
	err := UploadToGCS(context.Background(), bkt, "test-object.txt", bytes.NewReader(content), "text/plain", nil)
	if err != nil {
		t.Fatalf("UploadToGCS failed: %v", err)
	}

	obj, err := server.GetObject("test-bucket", "test-object.txt")
	if err != nil {
		t.Fatalf("failed to get object: %v", err)
	}

	if !bytes.Equal(obj.Content, content) {
		t.Errorf("expected content %q, got %q", content, obj.Content)
	}
	if obj.ContentType != "text/plain" {
		t.Errorf("expected content type %q, got %q", "text/plain", obj.ContentType)
	}
}

func TestUploadFile(t *testing.T) {
	server := fakestorage.NewServer([]fakestorage.Object{})
	t.Cleanup(server.Stop)

	client := server.Client()
	bkt := client.Bucket("test-bucket")
	if err := bkt.Create(context.Background(), "project", nil); err != nil {
		t.Fatalf("failed to create bucket: %v", err)
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-upload-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	content := []byte("file content")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	err = UploadFile(context.Background(), bkt, "uploaded-file.txt", tmpFile.Name())
	if err != nil {
		t.Fatalf("UploadFile failed: %v", err)
	}

	obj, err := server.GetObject("test-bucket", "uploaded-file.txt")
	if err != nil {
		t.Fatalf("failed to get object: %v", err)
	}

	if !bytes.Equal(obj.Content, content) {
		t.Errorf("expected content %q, got %q", content, obj.Content)
	}
}

func TestDownloadBucket(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		objects := []fakestorage.Object{
			{
				ObjectAttrs: fakestorage.ObjectAttrs{
					BucketName: "test-bucket",
					Name:       "folder/file1.txt",
				},
				Content: []byte("content 1"),
			},
			{
				ObjectAttrs: fakestorage.ObjectAttrs{
					BucketName: "test-bucket",
					Name:       "folder/file2.txt",
				},
				Content: []byte("content 2"),
			},
			{
				ObjectAttrs: fakestorage.ObjectAttrs{
					BucketName: "test-bucket",
					Name:       "folder/subfolder/", // Should be skipped
				},
				Content: []byte(""),
			},
			{
				ObjectAttrs: fakestorage.ObjectAttrs{
					BucketName: "test-bucket",
					Name:       "other-folder/file3.txt",
				},
				Content: []byte("content 3"),
			},
		}

		server := fakestorage.NewServer(objects)
		t.Cleanup(server.Stop)

		client := server.Client()
		bkt := client.Bucket("test-bucket")

		tmpDir := t.TempDir()

		err := DownloadBucket(context.Background(), bkt, "folder/", tmpDir)
		if err != nil {
			t.Fatalf("DownloadBucket failed: %v", err)
		}

		// Verify file1.txt
		content1, err := os.ReadFile(filepath.Join(tmpDir, "folder/file1.txt"))
		if err != nil {
			t.Fatalf("failed to read downloaded file1: %v", err)
		}
		if !bytes.Equal(content1, []byte("content 1")) {
			t.Errorf("expected content 1, got %q", content1)
		}

		// Verify file2.txt
		content2, err := os.ReadFile(filepath.Join(tmpDir, "folder/file2.txt"))
		if err != nil {
			t.Fatalf("failed to read downloaded file2: %v", err)
		}
		if !bytes.Equal(content2, []byte("content 2")) {
			t.Errorf("expected content 2, got %q", content2)
		}

		// Verify file3.txt is NOT downloaded because of the prefix
		if _, err := os.Stat(filepath.Join(tmpDir, "other-folder/file3.txt")); !os.IsNotExist(err) {
			t.Errorf("expected file3.txt to not exist, but it does")
		}
	})

	t.Run("path traversal", func(t *testing.T) {
		objects := []fakestorage.Object{
			{
				ObjectAttrs: fakestorage.ObjectAttrs{
					BucketName: "test-bucket",
					Name:       "../malicious.txt",
				},
				Content: []byte("malicious content"),
			},
		}

		server := fakestorage.NewServer(objects)
		t.Cleanup(server.Stop)

		client := server.Client()
		bkt := client.Bucket("test-bucket")

		tmpDir := t.TempDir()

		err := DownloadBucket(context.Background(), bkt, "", tmpDir)
		if err == nil {
			t.Fatalf("expected path traversal error, got nil")
		}
		if err.Error() != "invalid object name \"../malicious.txt\": path traversal attempt" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("relative dest dir", func(t *testing.T) {
		objects := []fakestorage.Object{
			{
				ObjectAttrs: fakestorage.ObjectAttrs{
					BucketName: "test-bucket",
					Name:       "file.txt",
				},
				Content: []byte("content"),
			},
		}

		server := fakestorage.NewServer(objects)
		t.Cleanup(server.Stop)

		client := server.Client()
		bkt := client.Bucket("test-bucket")

		// Use a relative directory
		destDir := "test-relative-dir"
		t.Cleanup(func() { os.RemoveAll(destDir) })

		err := DownloadBucket(context.Background(), bkt, "", destDir)
		if err != nil {
			t.Fatalf("DownloadBucket failed with relative dir: %v", err)
		}

		content, err := os.ReadFile(filepath.Join(destDir, "file.txt"))
		if err != nil {
			t.Fatalf("failed to read downloaded file: %v", err)
		}
		if !bytes.Equal(content, []byte("content")) {
			t.Errorf("expected content, got %q", content)
		}
	})
}
