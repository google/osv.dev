# Debian advisory converter

## Prerequisites

Clone the following two repositories:
- https://salsa.debian.org/security-tracker-team/security-tracker.git
- https://salsa.debian.org/webmaster-team/webwml.git

`git` also has to be installed and on the `PATH`, 
used to read modified dates of files.

## Run converter

### Usage:
```
go run main.go -o OUTPUT_DIR -adv-type {DSA,DLA,DTSA} -webwml WEBWML_REPO -security-tracker SECURITY_TRACKER_REPO
```

#### Options:
`-adv-type`: Specify advisory type:

- `DSA`: Debian security advisory
- `DLA`: Debian LTS security advisory
- `DTSA`: Debian testing security advisory

`-o`:
Output directory to place the converted osv `.json` files

`-webwml`:
Path to the cloned webwml repository

`-security-tracker`:
Path to the cloned security-tracker repository

### Example:
```
go run main.go -adv-type DSA -o ./output -webwml path/to/webwml/ -security-tracker path/to/security-tracker/
```
