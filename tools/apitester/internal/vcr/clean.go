package vcr

import (
	"bufio"
	"os"
	"strings"

	"github.com/tidwall/pretty"
)

func CleanCassettes() error {
	files, err := os.ReadDir("./testdata/cassettes")

	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		err := cleanCassetteFile("./testdata/cassettes/" + file.Name())

		if err != nil {
			return err
		}
	}

	return nil
}

func indent(str string, level int) string {
	indenting := strings.Repeat("  ", level)

	s := strings.Builder{}

	// we can't know how much indenting we'll do ahead of time, but we will be
	// at least the size of the string being indented and one indent level
	s.Grow(len(str) + len(indenting))

	for _, line := range strings.Split(str, "\n") {
		s.WriteString(indenting)
		s.WriteString(line)
		s.WriteString("\n")
	}

	return strings.TrimRight(s.String(), "\n")
}

func cleanCassetteBodyProperty(line string) string {
	// remove the existing "body" property definition
	line = strings.TrimPrefix(line, "    body: ")

	// turn the value into a JSON object, rather than a string
	line = strings.TrimPrefix(line, "\"")
	line = strings.TrimSuffix(line, "\"")

	// unescape any double quotes so that we're a proper JSON object
	line = strings.ReplaceAll(line, "\\\"", "\"")

	// make the JSON pretty, though without a trailing newline
	line = strings.TrimSpace(string(pretty.Pretty([]byte(line))))

	// indent the contents since this is YAML we're dealing with
	line = indent(line, 3)

	// return the "body" property with its new multi-line formatted string value
	return "    body: |\n" + line
}

func cleanCassetteFile(pathToFile string) error {
	f, err := os.Open(pathToFile)

	if err != nil {
		return err
	}

	defer f.Close()

	var lines []string

	skippingResponse := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		if skippingResponse && !strings.HasPrefix(line, "    ") {
			skippingResponse = false
		}

		if line == "  response:" {
			skippingResponse = true
		}

		if skippingResponse {
			continue
		}

		if strings.HasPrefix(line, "    body: \"") {
			line = cleanCassetteBodyProperty(line)
		}

		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	err = os.WriteFile(pathToFile, []byte(strings.Join(lines, "\n")+"\n"), 0600)

	if err != nil {
		return err
	}

	return nil
}
