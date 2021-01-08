# Sample scanner

This contains a sample OSV scanner written in Go.

Given a list of directories, this tool will recursively search for git
repositories and make requests to OSV to determine affected vulnerabilities.

This is intended to work with projects that use git submodules or a similar
mechanism where dependencies are checked out as real git repositories.

## Example

```bash
$ go run scanner.go -api_key=API_KEY /path/to/your/repo
```
