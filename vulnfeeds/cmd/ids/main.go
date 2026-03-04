// package main contains a utility for assigning IDs to OSV records.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	conflictFile       = ".id-allocator"
	conflictMarkerSize = 32
)

type fileFormat string

const (
	fileFormatJSON = fileFormat("json")
	fileFormatYAML = fileFormat("yaml")
)

var (
	validFormats      = []fileFormat{fileFormatYAML, fileFormatJSON}
	formatToExtension = map[fileFormat]string{
		fileFormatYAML: ".yaml",
		fileFormatJSON: ".json",
	}
)

func main() {
	prefix := flag.String("prefix", "", "Vulnerability prefix (e.g. \"PYSEC\".")
	dir := flag.String("dir", "", "Path to vulnerabilities.")
	format := flag.String("format", string(fileFormatYAML), "Format of OSV reports in the repository. Must be \"json\" or \"yaml\".")

	flag.Parse()

	logger.InitGlobalLogger()
	defer logger.Close()

	if *prefix == "" || *dir == "" {
		flag.Usage()
		return
	}

	if !slices.Contains(validFormats, fileFormat(*format)) {
		flag.Usage()
		return
	}

	if err := assignIDs(*prefix, *dir, fileFormat(*format)); err != nil {
		logger.Info("Failed to assign IDs", slog.Any("err", err))
		logger.Close() // os.Exit() doesn't call deferred functions
		os.Exit(1)     //nolint:gocritic
	}
}

func extractYearAndNum(prefix, filename string, format fileFormat) (int, int) {
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

func assignID(prefix, path string, format fileFormat, yearCounters map[int]int, defaultYear int) error {
	// Parse the existing vulnerability.
	readf, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer readf.Close()

	vuln, err := readVulnWithFormat(readf, format)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", format, err)
	}
	readf.Close()

	// If the vulnerability has a published date, use the year from that.
	// Otherwise, just default to the current year.
	year := defaultYear
	if vuln.GetPublished() != nil {
		year = vuln.GetPublished().AsTime().Year()
	}

	// Allocate a new ID and write the new file.
	id := yearCounters[year] + 1
	yearCounters[year] = id

	vuln.Id = fmt.Sprintf("%s-%d-%d", prefix, year, id)
	newPath := filepath.Join(filepath.Dir(path), vuln.GetId()+formatToExtension[format])

	writef, err := os.Create(newPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", newPath, err)
	}
	defer writef.Close()

	if err := writeVulnWithFormat(vuln, writef, format); err != nil {
		return fmt.Errorf("failed to serialize: %w", err)
	}

	logger.Info("Assigning", slog.String("path", path), slog.String("newPath", newPath))

	return os.Remove(path)
}

func assignIDs(prefix, dir string, format fileFormat) error {
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
		logger.Info("Nothing to allocate")
		return nil
	}

	logger.Info("Assigning IDs using detected maximums", slog.Any("counters", yearCounters))
	for _, path := range unassigned {
		if err := assignID(prefix, path, format, yearCounters, defaultYear); err != nil {
			return fmt.Errorf("failed to assign ID: %w", err)
		}
	}

	b := make([]byte, conflictMarkerSize)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("failed to generate random string: %w", err)
	}

	return os.WriteFile(filepath.Join(dir, conflictFile), []byte(hex.EncodeToString(b)), 0600)
}

func readVulnWithFormat(r io.Reader, format fileFormat) (*osvschema.Vulnerability, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var jsonBytes []byte
	switch format {
	case fileFormatJSON:
		jsonBytes = data
	case fileFormatYAML:
		jsonBytes, err = yaml.YAMLToJSON(data)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown file format: %v", format)
	}

	var v osvschema.Vulnerability
	if err := protojson.Unmarshal(jsonBytes, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func writeVulnWithFormat(v *osvschema.Vulnerability, w io.Writer, format fileFormat) error {
	marshaler := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}

	jsonBytes, err := marshaler.Marshal(v)
	if err != nil {
		return err
	}

	var data []byte
	switch format {
	case fileFormatJSON:
		data = jsonBytes
	case fileFormatYAML:
		data, err = yaml.JSONToYAML(jsonBytes)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown file format: %v", format)
	}

	// Ensure the output has a trailing newline to match the behavior of
	// json.Encoder, which was previously used.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	_, err = w.Write(data)

	return err
}
