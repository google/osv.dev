package ecosystem

import (
	"testing"
)

func TestRedHatLightwell_Get(t *testing.T) {
	p := NewProvider(nil)

	tests := []struct {
		name  string
		eco   string
		found bool
	}{
		{"maven suffix delegates", "Red Hat Lightwell:Maven", true},
		{"pypi suffix delegates", "Red Hat Lightwell:PyPI", true},
		{"unsupported suffix", "Red Hat Lightwell:npm", false},
		{"missing suffix", "Red Hat Lightwell", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := p.Get(tt.eco)
			if ok != tt.found {
				t.Errorf("Get(%q) found = %v, want %v", tt.eco, ok, tt.found)
			}
		})
	}
}
