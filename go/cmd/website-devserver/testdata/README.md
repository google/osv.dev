# OSV Website DevServer Test Data

This directory contains local mock data used by the OSV Website Development Server (`cmd/website-devserver`).

## How It Works
- **Hot Reloading**: Files in this directory are read live from disk on every request. You can add, edit, or remove vulnerability records and see updates immediately by refreshing the page.
- **Formats**: 
  - Vulnerability records **must be JSON** (`<ID>.json`).
  - Metadata files **must be YAML** (`<ID>.meta.yaml`).

---

## File Structure

### 1. Vulnerability Records (`<ID>.json`)
Each vulnerability file contains a standard [OSV Schema](https://ossf.github.io/osv-schema/) JSON record.

> [!NOTE]
> All relationships (**`aliases`**, **`related`**, and **`upstream`**) must be specified directly within the vulnerability JSON records themselves. Downstream hierarchies are automatically computed by inverting upstream relationships across the dataset.

**Minimal Example (`CVE-2021-44228.json`)**:
```json
{
  "id": "CVE-2021-44228",
  "modified": "2025-02-04T00:00:00Z",
  "published": "2023-08-14T00:00:00Z",
  "summary": "Log4Shell demo entry",
  "affected": [
    {
      "package": { "ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core" },
      "ranges": [
        { "type": "SEMVER", "events": [ { "introduced": "2.0-beta9" }, { "fixed": "2.15.0" } ] }
      ]
    }
  ],
  "aliases": ["GHSA-jfh8-c2jp-5v3q"],
  "related": ["CVE-2021-45046", "CVE-2021-45105"],
  "upstream": []
}
```

---

### 2. Companion Metadata Files (`<ID>.meta.yaml`)
To specify external repository metadata that cannot be derived from the vulnerability record itself (such as source repository mapping and link paths), create an optional companion `<ID>.meta.yaml` file.

**Example (`CVE-2021-44228.meta.yaml`)**:
```yaml
source: "cve-osv"
path: "2021/CVE-2021-44228.json"
```

#### Metadata Fields:
* `source`: Source repository name (e.g. `cve-osv`, `ubuntu`, `debian`, `suse`, `test`). Defaults to `"test"` if omitted.
* `path`: Relative file path within the source repository for generating human/source links. Defaults to the filename.

---

### 3. Source Repositories (`sources.yaml`)
Source repository definitions are loaded from `sources.yaml` in this directory (or the root `source.yaml`).

**Example (`sources.yaml`)**:
```yaml
- name: 'cve-osv'
  link: 'https://storage.googleapis.com/cve-osv-conversion/osv-output/'
  human_link: 'https://cve.org/CVERecord?id={{ BUG_ID }}'

- name: 'ubuntu'
  link: 'https://git.launchpad.net/ubuntu-cve-tracker/tree/'
  human_link: 'https://ubuntu.com/security/{{ BUG_ID }}'
```

---

## Tips
- Filenames should match the vulnerability ID (e.g., `CVE-2021-44228.json`).
- If an `<ID>.meta.yaml` is not present, `source` will default to `"test"` and `path` will default to the filename.