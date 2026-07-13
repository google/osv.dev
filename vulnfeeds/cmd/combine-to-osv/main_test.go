package main

import (
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPickAffectedInformation(t *testing.T) {
	repoA := "https://example.com/repo/a"
	repoB := "https://example.com/repo/b"

	// Base data for tests
	cve5Base := []*osvschema.Affected{
		{
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: repoA,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.1"},
					},
				},
			},
		},
	}

	nvdBase := []*osvschema.Affected{
		{
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: repoA,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.2"}, // Different fixed version
					},
				},
			},
		},
	}

	testCases := []struct {
		name         string
		cve5Affected []*osvschema.Affected
		nvdAffected  []*osvschema.Affected
		wantAffected []*osvschema.Affected
	}{
		{
			name:         "NVD has more affected packages",
			cve5Affected: cve5Base,
			nvdAffected: append(append([]*osvschema.Affected(nil), nvdBase...), &osvschema.Affected{
				Package: &osvschema.Package{Name: "another"},
			}),
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type:   osvschema.Range_GIT,
							Repo:   repoA,
							Events: cve5Base[0].GetRanges()[0].GetEvents(),
						},
					},
				},
				{
					Package: &osvschema.Package{Name: "another"},
				},
			},
		},
		{
			name:         "Same repo, same number of ranges, cve5 data is preferred",
			cve5Affected: cve5Base,
			nvdAffected:  nvdBase,
			// cve5's "1.0.1" fixed version should be kept
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type:   osvschema.Range_GIT,
							Repo:   repoA,
							Events: cve5Base[0].GetRanges()[0].GetEvents(),
						},
					},
				},
			},
		},
		{
			name:         "cve5 is empty, use nvd",
			cve5Affected: []*osvschema.Affected{},
			nvdAffected:  nvdBase,
			wantAffected: nvdBase,
		},
		{
			name:         "nvd is empty, use cve5",
			cve5Affected: cve5Base,
			nvdAffected:  []*osvschema.Affected{},
			wantAffected: cve5Base,
		},
		{
			name: "NVD provides missing introduced version",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Fixed: "1.0.1"}, // No introduced
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"}, // NVD has introduced
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "NVD provides missing fixed version",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"}, // No fixed
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0.9.0"},
								{Fixed: "1.0.2"}, // NVD has fixed
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
		},
		{
			name:         "NVD has unmatched repo, should be added",
			cve5Affected: cve5Base,
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoB, // Different repo
							Events: []*osvschema.Event{
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						cve5Base[0].GetRanges()[0],
						{
							Type: osvschema.Range_GIT,
							Repo: repoB,
							Events: []*osvschema.Event{
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Fixed overrides LastAffected (CVE5 has Fixed)",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{LastAffected: "1.0.2"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Fixed overrides LastAffected (NVD has Fixed)",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{LastAffected: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
		},
		{
			name: "Prefer constrained range (non-zero introduced)",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0.9.0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0.9.0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Prefer CPE_RANGE source over CVE5",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewStringValue("CPE_RANGE"),
								},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewStringValue("CPE_RANGE"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Prefer CPE_RANGE source over CVE5 when source is array",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("CPE_RANGE"),
											structpb.NewStringValue("REFERENCES"),
										},
									}),
								},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("CPE_RANGE"),
											structpb.NewStringValue("REFERENCES"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Cleanup last_affected if fixed exists",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Fixed: "1.0.1"},
								{LastAffected: "1.0.0"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Merge references-only range with CVE range",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{LastAffected: "1.0.1"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewStringValue("AFFECTED_FIELD"),
								},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "2c1762b85acb"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewStringValue("REFERENCES"),
								},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "2c1762b85acb"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("AFFECTED_FIELD"),
											structpb.NewStringValue("REFERENCES"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Merge references-only range (CVE-2016-15012): single fixed in base, references adds patch fixed, replace base fixed",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/forcedotcom/salesforcemobilesdk-windows",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "e4dd3fa3182d0fd382e229e0c25d1bfd8b77a711"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewStringValue("AFFECTED_FIELD"),
								},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/forcedotcom/salesforcemobilesdk-windows",
							Events: []*osvschema.Event{
								{Fixed: "83b3e91e0c1e84873a6d3ca3c5887eb5b4f5a3d8"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewStringValue("REFERENCES"),
								},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/forcedotcom/salesforcemobilesdk-windows",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "83b3e91e0c1e84873a6d3ca3c5887eb5b4f5a3d8"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"source": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("AFFECTED_FIELD"),
											structpb.NewStringValue("REFERENCES"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Multiple events, preferred source (CVE5) with more events is chosen",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Multiple events, NVD has more events and is chosen",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Same repo with different casing (e.g. GitHub case-insensitivity)",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/User/Repo",
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/user/repo",
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "https://github.com/User/Repo", // Should preserve casing of cve5's repo
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"}, // Preferred CVE5 fixed version
							},
						},
					},
				},
			},
		},
		{
			name: "Introduced and LastAffected (no fixed) should preserve LastAffected",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{LastAffected: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{LastAffected: "1.0.1"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{LastAffected: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Keep LastAffected if Introduced is in between Fixed and LastAffected",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
								{Introduced: "1.1.0"},
								{LastAffected: "1.1.5"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
								{Introduced: "1.1.0"},
								{LastAffected: "1.1.5"},
							},
						},
					},
				},
			},
		},
		{
			name: "Remove LastAffected if it comes before Fixed",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{LastAffected: "1.1.5"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "Keep LastAffected if it introduced between fixed",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{LastAffected: "1.1.1"},
								{Introduced: "1.2.0"},
								{Fixed: "1.2.1"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{LastAffected: "1.1.1"},
								{Introduced: "1.2.0"},
								{Fixed: "1.2.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "jumbled case",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{LastAffected: "1.1.1"},
								{LastAffected: "1.1.2"},
								{Introduced: "1.2.0"},
								{Fixed: "1.2.1"},
								{LastAffected: "1.2.4"},
								{Introduced: "1.2.3"},
								{LastAffected: "1.2.4"},
								{LastAffected: "1.2.5"},
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{LastAffected: "1.1.1"},
								{LastAffected: "1.1.2"},
								{Introduced: "1.2.0"},
								{Fixed: "1.2.1"},
								{Introduced: "1.2.3"},
								{LastAffected: "1.2.4"},
								{LastAffected: "1.2.5"},
							},
						},
					},
				},
			},
		},
	}

	// Sorter for comparing slices of Affected, ignoring order.
	sorter := cmpopts.SortSlices(func(a, b *osvschema.Affected) bool {
		if len(a.GetRanges()) == 0 || len(a.GetRanges()[0].GetRepo()) == 0 {
			return true
		}
		if len(b.GetRanges()) == 0 || len(b.GetRanges()[0].GetRepo()) == 0 {
			return false
		}

		return a.GetRanges()[0].GetRepo() < b.GetRanges()[0].GetRepo()
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a copy to avoid modifying the test case data
			cve5Actual := make([]*osvschema.Affected, len(tc.cve5Affected))
			copy(cve5Actual, tc.cve5Affected)

			gotAffected := pickAffectedInformation(cve5Actual, tc.nvdAffected)

			if diff := cmp.Diff(tc.wantAffected, gotAffected, sorter, protocmp.Transform()); diff != "" {
				t.Errorf("pickAffectedInformation() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCombineTwoOSVRecords(t *testing.T) {
	cve5Modified, _ := time.Parse(time.RFC3339, "2023-01-01T12:00:00Z")
	cve5Published, _ := time.Parse(time.RFC3339, "2023-01-01T10:00:00Z")
	nvdModified, _ := time.Parse(time.RFC3339, "2023-01-02T12:00:00Z")  // Later
	nvdPublished, _ := time.Parse(time.RFC3339, "2023-01-01T09:00:00Z") // Earlier

	cve5 := &osvschema.Vulnerability{
		Id:        "CVE-2023-1234",
		Modified:  timestamppb.New(cve5Modified),
		Published: timestamppb.New(cve5Published),
		Aliases:   []string{"GHSA-1234"},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5"},
		},
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{Name: "package-a"},
			},
		},
	}

	nvd := &osvschema.Vulnerability{
		Id:        "CVE-2023-1234",
		Modified:  timestamppb.New(nvdModified),
		Published: timestamppb.New(nvdPublished),
		Aliases:   []string{"GHSA-1234", "GHSA-5678"},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5"}, // Duplicate
			{Type: osvschema.Reference_WEB, Url: "https://example.com/nvd"},
		},
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{Name: "package-a"},
			},
			{
				Package: &osvschema.Package{Name: "package-b"},
			},
		},
	}

	expected := &osvschema.Vulnerability{
		Id:        "CVE-2023-1234",
		Modified:  timestamppb.New(nvdModified),  // Should take later date from NVD
		Published: timestamppb.New(nvdPublished), // Should take earlier date from NVD
		Aliases:   []string{"GHSA-1234", "GHSA-5678"},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5"},
			{Type: osvschema.Reference_WEB, Url: "https://example.com/nvd"},
		},
		// pickAffectedInformation prefers nvd if it has more packages
		Affected: nvd.GetAffected(),
	}

	got := combineTwoOSVRecords(cve5, nvd)

	// Sort slices for consistent comparison
	sort.Strings(got.GetAliases())
	sort.Strings(expected.GetAliases())
	sort.Slice(got.GetReferences(), func(i, j int) bool {
		return got.GetReferences()[i].GetUrl() < got.GetReferences()[j].GetUrl()
	})
	sort.Slice(expected.GetReferences(), func(i, j int) bool {
		return expected.GetReferences()[i].GetUrl() < expected.GetReferences()[j].GetUrl()
	})

	if diff := cmp.Diff(expected, got, protocmp.Transform()); diff != "" {
		t.Errorf("combineTwoOSVRecords() mismatch (-want +got):\n%s", diff)
	}
}

func TestCombineTwoOSVRecords_ReferencesDeterminism(t *testing.T) {
	cve5 := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5/A"},
			{Type: osvschema.Reference_REPORT, Url: "https://example.com/cve5/B"},
		},
	}

	nvd := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5/A"},
			{Type: osvschema.Reference_WEB, Url: "https://example.com/nvd/C"},
			{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/nvd/D"},
		},
	}

	var firstResult *osvschema.Vulnerability
	for i := range 10 {
		got := combineTwoOSVRecords(cve5, nvd)

		if i == 0 {
			firstResult = got
			continue
		}

		if diff := cmp.Diff(firstResult.GetReferences(), got.GetReferences(), protocmp.Transform()); diff != "" {
			t.Fatalf("Iteration %d produced different references result:\n%s", i, diff)
		}
	}
}
