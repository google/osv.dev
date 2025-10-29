package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type JSONReplaceRule struct {
	Path        string
	ReplaceFunc func(toReplace gjson.Result) any
}

// replaceJSONInput takes a gjson path and replaces all elements the path matches with the output of matcher
func replaceJSONInput(t *testing.T, jsonInput []byte, path string, matcher func(toReplace gjson.Result) any) []byte {
	t.Helper()

	pathArray := []string{}

	// If there are more than 2 #, sjson cannot replace them directly. Iterate out all individual entries
	if strings.Contains(path, "#") {
		// Get the path ending with #
		// E.g. results.#.packages.#.vulnerabilities => results.#.packages.#
		numOfEntriesPath := path[:strings.LastIndex(path, "#")+1]
		// This returns a potentially nested array of array lengths
		numOfEntries := gjson.GetBytes(jsonInput, numOfEntriesPath)

		// Use it to build up a list of concrete paths
		buildSJSONPaths(t, &pathArray, path, numOfEntries)
	} else {
		pathArray = append(pathArray, path)
	}

	var err error
	json := jsonInput
	for _, pathElem := range pathArray {
		res := gjson.GetBytes(jsonInput, pathElem)

		if !res.Exists() {
			continue
		}

		json, err = sjson.SetBytesOptions(json, pathElem, matcher(res), &sjson.Options{Optimistic: true})
		if err != nil {
			t.Fatalf("failed to set element")
		}
	}

	return json
}

func buildSJSONPaths(t *testing.T, pathToBuild *[]string, path string, structure gjson.Result) {
	t.Helper()

	if structure.IsArray() {
		// More nesting to go
		for i, res := range structure.Array() {
			buildSJSONPaths(
				t,
				pathToBuild,
				// Replace the first # with actual index
				strings.Replace(path, "#", strconv.Itoa(i), 1),
				res,
			)
		}
	} else {
		// Otherwise assume it is a number
		if strings.Count(path, "#") != 1 {
			t.Fatalf("programmer error: there should only be 1 # left")
		}
		for i2 := range int(structure.Int()) {
			newPath := strings.Replace(path, "#", strconv.Itoa(i2), 1)
			*pathToBuild = append(*pathToBuild, newPath)
		}
	}
}
