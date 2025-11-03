package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/apitester/internal/vcr"
)

func TestMain(m *testing.M) {
	err := vcr.CleanCassettes()
	if err != nil {
		fmt.Println("Error cleaning cassettes:", err)
		//nolint:revive // https://github.com/mgechev/revive/issues/1552
		os.Exit(1)
	}

	m.Run()

	dirty, err := snaps.Clean(m, snaps.CleanOpts{Sort: true})

	if err != nil {
		fmt.Println("Error cleaning snaps:", err)
		//nolint:revive // https://github.com/mgechev/revive/issues/1552
		os.Exit(1)
	}
	if dirty {
		fmt.Println("Some snapshots were outdated.")
		//nolint:revive // https://github.com/mgechev/revive/issues/1552
		os.Exit(1)
	}
}
