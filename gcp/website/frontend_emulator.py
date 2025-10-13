# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Frontend emulator to mock local data instead of from GCP"""
import os
import json
import yaml
from google.protobuf import json_format
from osv import tests
from osv import sources
from osv import vulnerability_pb2
from google.cloud import ndb
import osv
import datetime
from gcp.workers.alias import upstream_computation, alias_computation

if __name__ == '__main__':
  # The datastore emulator needs to be started before main is imported
  # to make the global ndb client use the emulator.
  with tests.datastore_emulator() as em:
    import main
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)

      # Load OSV files from the repo testdata directory.
      def _load_osv_vuln(path: str) -> vulnerability_pb2.Vulnerability | None:
        """Parse a single vulnerability from an OSV file."""
        data = _read_osv_file(path)
        vulnerability = _dict_to_vuln(data, path)
        if vulnerability:
          return vulnerability

        print(f'[emulator] No valid OSV record found in {path}')
        return None

      def _vulnerability_to_bug(
          vulnerability: vulnerability_pb2.Vulnerability) -> osv.Bug:
        """Convert a parsed vulnerability into a datastore Bug entity."""
        bug_entity = osv.Bug(
            id=vulnerability.id,
            db_id=vulnerability.id,
            public=True,
            source='test',
            status=osv.BugStatus.PROCESSED)
        bug_entity.update_from_vulnerability(vulnerability)
        if vulnerability.HasField('modified'):
          bug_entity.import_last_modified = vulnerability.modified.ToDatetime(
              datetime.UTC)
          if not bug_entity.timestamp:
            bug_entity.timestamp = vulnerability.modified.ToDatetime(
                datetime.UTC)
        if not bug_entity.timestamp:
          bug_entity.timestamp = datetime.datetime.now(datetime.UTC)
        return bug_entity

      def _read_osv_file(path: str) -> object | None:
        """Read and parse raw data from an OSV file."""
        try:
          with open(path) as fh:
            ext = os.path.splitext(path)[1].lower()
            if ext in sources.YAML_EXTENSIONS:
              return yaml.load(fh, Loader=sources.NoDatesSafeLoader)
            if ext in sources.JSON_EXTENSIONS:
              return json.load(fh)
        except Exception as error:
          print(f'[emulator] Failed to read {path}: {error}')
          return None

        print(f'[emulator] Unsupported file extension for {path}')
        return None

      def _dict_to_vuln(data: object,
                        path: str) -> vulnerability_pb2.Vulnerability | None:
        """Convert raw dict data into a Vulnerability proto."""
        if not isinstance(data, dict):
          return None

        vuln_id = data.get('id')
        if not vuln_id:
          return None

        vulnerability = vulnerability_pb2.Vulnerability()
        try:
          json_format.ParseDict(data, vulnerability, ignore_unknown_fields=True)
        except Exception as error:
          print(f'[emulator] Failed to convert entry in {path}: {error}')
          return None

        return vulnerability if vulnerability.id else None

      def _load_dir(emulator, dir_path: str):
        """Load all OSV files from a directory into the emulator."""
        emulator.reset()
        for root, _, files in os.walk(dir_path):
          for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (*sources.YAML_EXTENSIONS, *sources.JSON_EXTENSIONS):
              continue
            fpath = os.path.join(root, fname)
            vulnerability = _load_osv_vuln(fpath)
            if not vulnerability:
              continue

            bug = _vulnerability_to_bug(vulnerability)
            bug.put()

        # Compute upstream/alias groups based on loaded bugs.
        upstream_computation.main()
        alias_computation.main()

        for b in osv.Bug.query():
          b.put()

      testdata_dir = os.path.join(os.path.dirname(__file__), 'testdata', 'osv')
      if os.path.isdir(testdata_dir):
        _load_dir(em, testdata_dir)
      else:
        print('No testdata found; starting emulator with empty dataset.')
    main.app.run(host='127.0.0.1', port=8000, debug=False)
