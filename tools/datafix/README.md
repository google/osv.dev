
## About

There are multiple utility tools in this directory:

- `delete_bugs_with_source.py`
- `delete_invalid.py`
- `reimport_gcs_record.py`
- `reput_bugs.py`
- `withdraw_invalid.py`

Each have their own usecases specified in the file. 

`reput_bugs.py` must be run in a python environment with osv loaded as a library, in order to accurately query the `osv.Bug` type. One such env can be retrieved by running `poetry shell` inside the `/tools/datafix` directory.
