package main

import (
	"reflect"
	"testing"
)

func TestRemoveEmptySlicesAndMaps(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "empty map",
			input:    map[string]any{},
			expected: nil,
		},
		{
			name:     "empty slice",
			input:    []any{},
			expected: nil,
		},
		{
			name: "nested empty objects",
			input: map[string]any{
				"a": []any{},
				"b": map[string]any{},
			},
			expected: nil,
		},
		{
			name: "mixed populated and empty",
			input: map[string]any{
				"a": []any{},
				"b": map[string]any{"c": "d"},
			},
			expected: map[string]any{"b": map[string]any{"c": "d"}},
		},
		{
			name: "deeply nested empty objects that become empty",
			input: map[string]any{
				"a": []any{
					map[string]any{},
				},
				"b": map[string]any{
					"c": map[string]any{},
				},
			},
			expected: nil,
		},
		{
			name: "slice with values and empty values",
			input: []any{
				"a",
				map[string]any{},
				"b",
			},
			expected: []any{"a", "b"},
		},
		{
			name: "example ecosystem_specific",
			input: map[string]any{
				"affected": []any{
					map[string]any{
						"database_specific":  map[string]any{"source": "test"},
						"ecosystem_specific": map[string]any{},
						"package":            map[string]any{"ecosystem": "Alpine", "name": "krb5"},
					},
				},
			},
			expected: map[string]any{
				"affected": []any{
					map[string]any{
						"database_specific": map[string]any{"source": "test"},
						"package":           map[string]any{"ecosystem": "Alpine", "name": "krb5"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := removeEmptySlicesAndMaps(tt.input)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("removeEmptySlicesAndMaps() = %#v, want %#v", actual, tt.expected)
			}
		})
	}
}
