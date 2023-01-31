# Debian advisory converter (WIP)

## Prerequisites

Clone the following two repositories:
- https://salsa.debian.org/security-tracker-team/security-tracker.git
- https://salsa.debian.org/webmaster-team/webwml.git

`git` also has to be installed and on the `PATH`, 
used to read modified dates of files 

Running the `first_package_finder.py` also requires internet connection.

## Run converter

### Usage:
```
usage: convert_debian.py [-h] -o OUTPUT_DIR [--adv_type {DSA,DLA,DTSA}] webwml_repo security_tracker_repo
```

#### Options:
`--adv_type`: Specify advisory type:

- `DSA`: Debian security advisory
- `DLA`: Debian LTS security advisory
- `DTSA`: Debian testing security advisory

`--output-dir, -o`:
Output directory to place the converted osv `.json` files

### Example:
```
python convert_debian.py --adv_type DSA -o ./output path/to/webwml/ path/to/security-tracker-master/
```

## Run first_package_finder

first_package_finder will output `first_package_cache.json.gz` in the working
directory. 

### Example:
```
python first_package_finder.py
```