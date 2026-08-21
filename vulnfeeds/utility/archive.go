// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utility

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxTarEntrySize = 1 * 1024 * 1024 * 1024 // 1GB max entry size limit for decompression bomb protection

// CreateTarArchive archives all files and subdirectories in sourceDir into the tar writer.
func CreateTarArchive(sourceDir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	sourceDir = filepath.Clean(sourceDir)

	return filepath.Walk(sourceDir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if file == sourceDir {
			return nil
		}

		relPath, err := filepath.Rel(sourceDir, file)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", file, err)
		}

		tarName := filepath.ToSlash(relPath)
		if fi.IsDir() {
			tarName += "/"
		}

		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", file, err)
		}
		hdr.Name = tarName

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", file, err)
		}

		if fi.Mode().IsRegular() {
			f, err := os.Open(file)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", file, err)
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return fmt.Errorf("failed to copy file %s to tar: %w", file, err)
			}
		}

		return nil
	})
}

// sanitizeTarPath validates that an archive entry name does not escape destDir (Zip Slip protection)
// and returns the canonical target path.
func sanitizeTarPath(destDir, name string) (string, error) {
	cleanDest := filepath.Clean(destDir)
	cleanName := filepath.Clean(filepath.FromSlash(name))

	// Reject absolute paths and parent directory traversals
	if filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, string(os.PathSeparator)) {
		return "", fmt.Errorf("illegal absolute path in tar archive: %s", name)
	}
	if cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal attempt in tar archive: %s", name)
	}

	targetPath := filepath.Join(cleanDest, cleanName)
	cleanTarget := filepath.Clean(targetPath)

	// Ensure target path is strictly inside cleanDest
	rel, err := filepath.Rel(cleanDest, cleanTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal attempt in tar archive: %s", name)
	}

	return cleanTarget, nil
}

// ExtractTarArchive extracts a tar archive stream into the destination directory,
// protecting against path traversal (Zip Slip), symlink hijacking, and decompression bombs.
func ExtractTarArchive(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	cleanDest := filepath.Clean(destDir)

	if err := os.MkdirAll(cleanDest, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", cleanDest, err)
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar entry: %w", err)
		}

		targetPath, err := sanitizeTarPath(cleanDest, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if targetPath == cleanDest {
				continue
			}
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if targetPath == cleanDest {
				return fmt.Errorf("tar entry attempts to overwrite destination directory: %s", hdr.Name)
			}
			dir := filepath.Dir(targetPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory for file %s: %w", targetPath, err)
			}

			// Clean existing file to avoid writing through pre-existing symlinks
			_ = os.Remove(targetPath)

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, io.LimitReader(tr, maxTarEntrySize)); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file content %s: %w", targetPath, err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("failed to close file %s: %w", targetPath, err)
			}
		default:
			// Skip unsupported entry types (symlinks, devices, pipes) to prevent link-based traversal attacks
			continue
		}
	}

	return nil
}
