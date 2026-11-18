package main

import "testing"

func TestGCSOutputPrefix(t *testing.T) {
	tests := []struct {
		name      string
		outputDir string
		advType   AdvisoryType
		want      string
	}{
		{
			name:      "DSA without prefix",
			outputDir: "",
			advType:   AdvisoryTypeDSA,
			want:      "dsa-osv",
		},
		{
			name:      "DLA without prefix",
			outputDir: "",
			advType:   AdvisoryTypeDLA,
			want:      "dla-osv",
		},
		{
			name:      "DTSA without prefix",
			outputDir: "",
			advType:   AdvisoryTypeDTSA,
			want:      "dtsa-osv",
		},
		{
			name:      "DLA with prefix",
			outputDir: "custom-prefix",
			advType:   AdvisoryTypeDLA,
			want:      "custom-prefix/dla-osv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gcsOutputPrefix(tt.outputDir, tt.advType); got != tt.want {
				t.Errorf("gcsOutputPrefix(%q, %q) = %q, want %q", tt.outputDir, tt.advType, got, tt.want)
			}
		})
	}
}
