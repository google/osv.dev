package main

import (
	"bufio"
	"os"
	"strings"
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
