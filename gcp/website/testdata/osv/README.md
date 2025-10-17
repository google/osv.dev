# OSV Frontend Emulator Test Data

This directory is for test data used by the OSV frontend emulator.

## Rules
- File types: `.json`, `.yaml`, `.yml`
- Multiple files and subdirectories are supported; the emulator loads all recursively.
- Each file must contain exactly one OSV vulnerability entry (at least an `id`).

## Minimal example (JSON):
```
{
  "id": "OSV-TEST-1",
  "modified": "2025-03-01T00:00:00Z",
  "published": "2025-03-01T00:00:00Z",
  "summary": "Example vuln",
  "details": "Demo entry for emulator.",
  "affected": [
    {
      "package": { "ecosystem": "PyPI", "name": "demo-lib" },
      "ranges": [
        { "type": "SEMVER", "events": [ {"introduced": "0"}, {"fixed": "1.2.0"} ] }
      ]
    }
  ],
  "aliases": ["CVE-2025-0001"],
  "upstream": []
}
```

> [!NOTE]
> Ideally, file names should match the vulnerability ID (e.g., `OSV-TEST-1.json`), and files should not include characters that do not work well with all systems (e.g., colons).