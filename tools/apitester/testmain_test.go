package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

func TestMain(m *testing.M) {
	err := CleanCassettes()
	if err != nil {
		fmt.Println("Error cleaning cassettes:", err)
		os.Exit(1)
	}

	m.Run()

	dirty, err := snaps.Clean(m, snaps.CleanOpts{Sort: true})

	if err != nil {
		fmt.Println("Error cleaning snaps:", err)
		os.Exit(1)
	}
	if dirty {
		fmt.Println("Some snapshots were outdated.")
		os.Exit(1)
	}
}
