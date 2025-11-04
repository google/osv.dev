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

	// split on the first # for array items
	pathToArray, restOfPath, match := strings.Cut(path, ".#.")

	if !match {
		if !strings.HasSuffix(path, ".#") {
			return []string{path}
		}

		pathToArray = strings.TrimSuffix(path, ".#")
	}

	r := gjson.GetBytes(jsonInput, pathToArray)

	// if property exists and is actually an array, build out the path to each item
	// within that array
	if r.IsArray() {
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

	return []string{}
}

// replaceJSONInput takes a gjson path and replaces all elements the path matches with the output of matcher
func replaceJSONInput(t *testing.T, jsonInput []byte, path string, matcher func(toReplace gjson.Result) any) []byte {
	t.Helper()

	pathArray := []string{}

	pathArray = expandArrayPaths(t, jsonInput, path)

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
