package utility

import "regexp"

// SliceEqual returns true if two slices have identical items in the same order
func SliceEqual[K comparable](a []K, b []K) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SliceEqualUnordered returns true if two slices have identical items, in any order
func SliceEqualUnordered[K comparable](a []K, b []K) bool {
	if len(a) != len(b) {
		return false
	}
	aSet := make(map[K]struct{}, len(a))
	bSet := make(map[K]struct{}, len(b))
	for i := 0; i < len(a); i++ {
		aSet[a[i]] = struct{}{}
		bSet[b[i]] = struct{}{}
	}
	for k, _ := range aSet {
		_, ok := bSet[k]
		if !ok {
			return false
		}
	}
	return true
}

// Checks if a URL is to a supported repo.
func IsRepoURL(url string) bool {
	re := regexp.MustCompile(`http[s]?:\/\/(?:c?git(?:hub|lab)?)\.|\.git$`)

	return re.MatchString(url)
}
