package cves

import (
	"reflect"
	"testing"
)

func TestParseCPE(t *testing.T) {

	tests := []struct {
		description       string
		inputCPEString    string
		expectedCPEStruct *CPE
		expectedError     bool
	}{
		{
			description: "invalid input (empty string)", inputCPEString: "", expectedCPEStruct: nil, expectedError: true,
		},

		{
			description: "invalid input (corrupt)", inputCPEString: "fnord:2.3:h:intel:core_i3-1005g1:-:*:*:*:*:*:*:*", expectedCPEStruct: nil, expectedError: true,
		},
		{
			description: "valid input (hardware)", inputCPEString: "cpe:2.3:h:intel:core_i3-1005g1:-:*:*:*:*:*:*:*", expectedCPEStruct: &CPE{
				CPEVersion: "2.3", Part: "h", Vendor: "intel", Product: "core_i3-1005g1", Version: "-", Update: "*", Edition: "*", Language: "*", SWEdition: "*", TargetSw: "*", TargetHw: "*", Other: "*"}, expectedError: false,
		},
		{
			description: "valid input (software)", inputCPEString: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", expectedCPEStruct: &CPE{CPEVersion: "2.3", Part: "a", Vendor: "gitlab", Product: "gitlab", Version: "*", Update: "*", Edition: "*", Language: "*", SWEdition: "community", TargetSw: "*", TargetHw: "*", Other: "*"}, expectedError: false,
		},
	}

	for i, tc := range tests {
		got, err := ParseCPE(tc.inputCPEString)
		if err != nil && !tc.expectedError {
			t.Errorf("test %d: ParseCPE for %q unexpectedly errored, got %v", i+1, tc.inputCPEString, err)
		}
		if !reflect.DeepEqual(got, tc.expectedCPEStruct) {
			t.Errorf("test %d: ParseCPE for %q was incorrect, got: %#v, expected: %#v", i+1, tc.inputCPEString, got, tc.expectedCPEStruct)
		}
	}
}
