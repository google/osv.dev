// Package jsonreplace handles replacing parts of JSON with placeholders based on rules
package jsonreplace

import (
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type Rule struct {
	Path        string
	ReplaceFunc func(toReplace gjson.Result) any
}

func DoBytes(t *testing.T, json []byte, rules []Rule) []byte {
	t.Helper()

	for _, rule := range rules {
		json = replaceJSONInput(t, json, rule.Path, rule.ReplaceFunc)
	}

	return json
}

func expandArrayPaths(t *testing.T, jsonInput []byte, path string) []string {
	t.Helper()

	// split on the first intermediate #, if present
	pathToArray, restOfPath, hasArrayPlaceholder := strings.Cut(path, ".#.")

	// if there is no intermediate placeholder, check for (and cut) a terminal one
	if !hasArrayPlaceholder {
		pathToArray, hasArrayPlaceholder = strings.CutSuffix(path, ".#")
	}

	// if there are no array placeholders in the path, just return it
	if !hasArrayPlaceholder {
		return []string{path}
	}

	r := gjson.GetBytes(jsonInput, pathToArray)

	// skip properties that are not arrays
	if !r.IsArray() {
		return []string{}
	}

	// if property exists and is actually an array, build out the path to each item
	// within that array
	paths := make([]string, 0, len(r.Array()))

	for i := range r.Array() {
		static := pathToArray + "." + strconv.Itoa(i)

		if restOfPath != "" {
			static += "." + restOfPath
		}
		paths = append(paths, expandArrayPaths(t, jsonInput, static)...)
	}

	return paths
}

// replaceJSONInput takes a gjson path and replaces all elements the path matches with the output of matcher
func replaceJSONInput(t *testing.T, jsonInput []byte, path string, replacer func(toReplace gjson.Result) any) []byte {
	t.Helper()

	var err error
	json := jsonInput
	for _, pathElem := range expandArrayPaths(t, jsonInput, path) {
		res := gjson.GetBytes(jsonInput, pathElem)

		if !res.Exists() {
			continue
		}

		// optimistically replace the element, since we know at this point it does exist
		json, err = sjson.SetBytesOptions(json, pathElem, replacer(res), &sjson.Options{Optimistic: true})
		if err != nil {
			t.Fatalf("failed to set element")
		}
	}

	return json
}
