package main

import (
	"context"

	"github.com/google/osv.dev/go/internal/repos"
)

func main() {
	ctx := context.Background()
	_, err := repos.CloneToDir(ctx, "https://github.com/rustsec/advisory-db.git", "/usr/local/google/home/michaelkedar/sourcerepos/0545fb845c0fcfffaefd11f0caf746e0fd591182148caf7dda98b1de7d4e2e62", true)
	if err != nil {
		panic(err)
	}

}
