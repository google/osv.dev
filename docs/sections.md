# OSV API
---

### How does the API work?

The API currently accepts a git commit hash or a `(package, version number)` and returns the
list of vulnerabilities that are present for that version.

# Getting Started
---

### Using the API

Browse the rest of the documentation for details on the
API.

For some quick examples, run:

```
curl -X POST -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
    "https://api.osv.dev/v1/query"
```

```
curl -X POST -d \
          '{"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
          "https://api.osv.dev/v1/query"
```
