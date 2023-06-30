
## About

Use this tool to create a list of file hashes and send it to the determineversion API 
to attempt to identify the given library and its version.

## Usage

To scan a single library, run with the following command:

`go run . -lib path/to/library`

For directories than contain multiple libraries as top level subdirectories:

`go run . -dir /path/to/libs/dir`
