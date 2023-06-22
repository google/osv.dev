package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"gopkg.in/yaml.v2"
)

const (
	conflictFile       = ".id-allocator"
	conflictMarkerSize = 32
)

type FileFormat string

const (
	FileFormatJSON = FileFormat("json")
	FileFormatYAML = FileFormat("yaml")
)

var (
	validFormats      = []FileFormat{FileFormatYAML, FileFormatJSON}
	formatToExtension = map[FileFormat]string{
		FileFormatYAML: ".yaml",
		FileFormatJSON: ".json",
	}
)

func main() {
	rand.Seed(time.Now().Unix())
	prefix := flag.String("prefix", "", "Vulnerability prefix (e.g. \"PYSEC\".")
	dir := flag.String("dir", "", "Path to vulnerabilites.")
	format := flag.String("format", string(FileFormatYAML), "Format of OSV reports in the repository. Must be \"json\" or \"yaml\".")

	flag.Parse()

	if *prefix == "" || *dir == "" {
		flag.Usage()
		return
	}

	if !slices.Contains(validFormats, FileFormat(*format)) {
		flag.Usage()
		return
	}

	if err := assignIDs(*prefix, *dir, FileFormat(*format)); err != nil {
		fmt.Printf("Failed to assign IDs: %v", err)
		os.Exit(1)
	}
}

func extractYearAndNum(prefix, filename string, format FileFormat) (int, int) {
	// Extract year and num from "PREFIX-YEAR-NUM"
	parts := strings.Split(strings.TrimSuffix(filename, formatToExtension[format]), "-")
	if len(parts) != 3 {
		return 0, 0
	}

	if parts[0] != prefix {
		return 0, 0
	}

	year, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0
	}

	num, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0
	}

	return year, num
}

func isUnassigned(prefix, filename string) bool {
	return strings.HasPrefix(filename, prefix+"-0000-")
}

func assignID(prefix, path string, format FileFormat, yearCounters map[int]int, defaultYear int) error {
	// Parse the existing vulnerability.
	readf, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer readf.Close()

	vuln, err := ReadVulnWithFormat(readf, format)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", format, err)
	}
	readf.Close()

	// If the vulnerability has a published date, use the year from that.
	// Otherwise, just default to the current year.
	year := defaultYear
	if !vuln.Published.IsZero() {
		year = vuln.Published.Year()
	}

	// Allocate a new ID and write the new file.
	id := yearCounters[year] + 1
	yearCounters[year] = id

	vuln.ID = fmt.Sprintf("%s-%d-%d", prefix, year, id)
	newPath := filepath.Join(filepath.Dir(path), vuln.ID+formatToExtension[format])

	writef, err := os.Create(newPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", newPath, err)
	}
	defer writef.Close()

	if err := WriteVulnWithFormat(vuln, writef, format); err != nil {
		return fmt.Errorf("failed to serialize: %w", err)
	}

	fmt.Printf("Assigning %s to %s\n", path, newPath)
	return os.Remove(path)
}

func assignIDs(prefix, dir string, format FileFormat) error {
	defaultYear := time.Now().Year()
	var unassigned []string
	yearCounters := map[int]int{}

	// Look for unassigned vulnerabilities, as well as the maximum allocated IDs for every year.
	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to access %s: %w", path, err)
		}
		if info.IsDir() {
			return nil
		}

		filename := filepath.Base(path)
		if isUnassigned(prefix, filename) {
			unassigned = append(unassigned, path)
			return nil
		}

		year, num := extractYearAndNum(prefix, filename, format)
		if year == 0 || num == 0 {
			return nil
		}

		if num > yearCounters[year] {
			yearCounters[year] = num
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk: %w", err)
	}

	if len(unassigned) == 0 {
		fmt.Printf("Nothing to allocate")
		return nil
	}

	fmt.Printf("Assigning IDs using detected maximums: %v\n", yearCounters)
	for _, path := range unassigned {
		if err := assignID(prefix, path, format, yearCounters, defaultYear); err != nil {
			return fmt.Errorf("failed to assign ID: %w", err)
		}
	}

	b := make([]byte, conflictMarkerSize)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("failed to generate random string: %w", err)
	}

	return ioutil.WriteFile(filepath.Join(dir, conflictFile), []byte(hex.EncodeToString(b)), 0644)
}

func ReadVulnWithFormat(r io.Reader, format FileFormat) (*models.Vulnerability, error) {
	var v models.Vulnerability
	switch format {
	case FileFormatJSON:
		dec := json.NewDecoder(r)
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
	case FileFormatYAML:
		dec := yaml.NewDecoder(r)
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown file format: %v", format)
	}
	return &v, nil
}

func WriteVulnWithFormat(v *models.Vulnerability, w io.Writer, format FileFormat) error {
	switch format {
	case FileFormatJSON:
		enc := json.NewEncoder(w)
		return enc.Encode(v)
	case FileFormatYAML:
		enc := yaml.NewEncoder(w)
		return enc.Encode(v)
	default:
		return fmt.Errorf("unknown file format: %v", format)
	}
}
