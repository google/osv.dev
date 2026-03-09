package main

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/storage/memory"
)

func main() {
	remoteConfig := &config.RemoteConfig{
		Name: "source",
		URLs: []string{
			"https://github.com/andrewpollock/mybogusrepo",
		},
	}
	repo := git.NewRemote(memory.NewStorage(), remoteConfig)
	_, err := repo.List(&git.ListOptions{PeelingOption: git.AppendPeeled})
	fmt.Printf("Error: %v\n", err)
	fmt.Printf("Type: %T\n", err)
}
