package lockfiles

import (
	"log"
	"os"
)
import "github.com/BurntSushi/toml"

type CargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type CargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []CargoLockPackage `toml:"package"`
}

// ScanCargoFile Returns an array of PURLs of packages
func ScanCargoFile(file *os.File) []string {
	decoder := toml.NewDecoder(file)

	var lockOutput CargoLockFile
	_, err := decoder.Decode(&lockOutput)
	if err != nil {
		log.Fatalf("Failed to decode cargo.lock file %s", err)
	}

	output := make([]string, 0, len(lockOutput.Packages))
	for _, lockPackage := range lockOutput.Packages {
		output = append(output, "pkg:cargo/"+lockPackage.Name+"@"+lockPackage.Version)
	}
	return output
}
