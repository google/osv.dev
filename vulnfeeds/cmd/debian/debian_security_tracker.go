package main

type CVE struct {
	Description string `json:"description"`
	DebianBug   int
	Scope       string `json:"scope"`
	Releases    map[string]struct {
		Status       string            `json:"status"`
		Repositories map[string]string `json:"repositories"`
		FixedVersion string            `json:"fixed_version"`
		Urgency      string            `json:"urgency"`
	} `json:"releases"`
}

type DebianSecurityTrackerData map[string]map[string]CVE
