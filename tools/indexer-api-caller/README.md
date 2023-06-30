
## About

Use this tool to create a list of file hashes and send it to the determineversion API 
to attempt to identify the given library and its version.

## Usage

To scan a single library, run with the following command:

`go run . -lib path/to/library`

If you have multiple libraries that you would like to version within a directory, use the following command:

`go run . -dir /path/to/libs/dir`
