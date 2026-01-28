package main

type AlpineSecDB struct {
	ApkURL        string   `json:"apkurl"`
	Archs         []string `json:"archs"`
	RepoName      string   `json:"reponame"`
	URLPrefix     string   `json:"urlprefix"`
	DistroVersion string   `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			SecFixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}
