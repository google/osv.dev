package main

type Release struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

type CVE struct {
	Description string `json:"description"`
	DebianBug   int
	Scope       string             `json:"scope"`
	Releases    map[string]Release `json:"releases"`
}

type DebianSecurityTrackerData map[string]map[string]CVE
