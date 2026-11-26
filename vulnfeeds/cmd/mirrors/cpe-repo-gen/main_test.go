package main

import "testing"

func TestMaybeGetSourceRepoFromDebianShortNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	for _, pkg := range []string{"", "lib", "a"} {
		if got := MaybeGetSourceRepoFromDebian(dir, pkg); got != "" {
			t.Errorf("MaybeGetSourceRepoFromDebian(%q, %q) = %q, want empty string", dir, pkg, got)
		}
	}
}

func TestMaybeTranslateSavannahURLInvalid(t *testing.T) {
	t.Parallel()

	invalidURL := "https://savannah.gnu.org/\x7f"
	got, translated := MaybeTranslateSavannahURL(invalidURL)
	if translated {
		t.Errorf("MaybeTranslateSavannahURL(%q) translated = true, want false", invalidURL)
	}
	if got != invalidURL {
		t.Errorf("MaybeTranslateSavannahURL(%q) = %q, want %q", invalidURL, got, invalidURL)
	}
}
