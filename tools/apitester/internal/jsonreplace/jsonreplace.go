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

// func replaceJSONInput2(t *testing.T, jsonInput []byte, path string, matcher func(toReplace gjson.Result) any) []byte {
// 	t.Helper()
//
// 	allPaths := []string{}
//
// 	// gjson.GetBytes(jsonInput, "").Raw
//
// 	return jsonInput
// }

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

	// can this ever happen...?
	return []string{}

	// // x.#.y.#.z
	// // x.#.y.#.z -> [x.#, y.#.z]
	//
	// // x.#.y.#.z
	// //  -> x.#.y.0.z
	// //  -> x.#.y.1.z
	// //  -> x.#.y.2.z
	// // x.#.y.#
	// // x.#.y
	// expandedPaths := []string{}
	//
	// // x.#.y -> x.0.y
	//
	// i := 0
	//
	// for {
	// 	static := strings.Replace(path, "#", strconv.Itoa(i), 1)
	//
	// 	if !gjson.GetBytes(jsonInput, static).Exists() {
	// 		break
	// 	}
	//
	// 	expandedPaths = append(expandedPaths, static)
	// 	i++
	// }
	//
	// return expandedPaths
}

// func replace(t *testing.T, jsonInput []byte, path string, matcher func(toReplace gjson.Result) any) []byte {
// 	t.Helper()
//
//
// }

// replaceJSONInput takes a gjson path and replaces all elements the path matches with the output of matcher
func replaceJSONInput(t *testing.T, jsonInput []byte, path string, matcher func(toReplace gjson.Result) any) []byte {
	t.Helper()

	pathArray := []string{}

	pathArray = expandArrayPaths(t, jsonInput, path)

	// if path == "items.#.subStruct.subitems.#"

	// // If there are more than 2 #, sjson cannot replace them directly. Iterate out all individual entries
	// if strings.Contains(path, "#") {
	// 	// Get the path ending with #
	// 	// E.g. results.#.packages.#.vulnerabilities => results.#.packages.#
	// 	numOfEntriesPath := path[:strings.LastIndex(path, "#")+1]
	// 	// This returns a potentially nested array of array lengths
	// 	numOfEntries := gjson.GetBytes(jsonInput, numOfEntriesPath)
	//
	// 	// Use it to build up a list of concrete paths
	// 	buildSJSONPaths(t, &pathArray, path, numOfEntries)
	// } else {
	// 	pathArray = append(pathArray, path)
	// }

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
			t.Errorf("programmer error: there should only be 1 # left")
		}
		for i2 := range int(structure.Int()) {
			newPath := strings.Replace(path, "#", strconv.Itoa(i2), 1)
			*pathToBuild = append(*pathToBuild, newPath)
		}
	}
}
