#!/usr/bin/env python3
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
"""Run osv-linter on all OSV records."""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import zipfile

from google.cloud import ndb, storage

import osv.logs
from osv.models import utcnow

# The Go binary is copied to /usr/local/bin in the Dockerfile
OSV_LINTER = 'osv-linter'
VULN_BUCKET = 'osv-test-vulnerabilities'
ZIP_FILE_PATH = 'all.zip'
TEST_DATA = '/linter/test_data'
GCP_PROJECT = 'oss-vdb-test'

ERROR_CODE_MAPPING = {
    'REC:001': osv.ImportFindings.INVALID_RECORD,
    'REC:002': osv.ImportFindings.INVALID_ALIASES,
    'REC:003': osv.ImportFindings.INVALID_UPSTREAM,
    'REC:004': osv.ImportFindings.INVALID_RELATED,
    'RNG:001': osv.ImportFindings.INVALID_RANGE,
    'RNG:002': osv.ImportFindings.INVALID_RANGE,
    'PKG:001': osv.ImportFindings.INVALID_PACKAGE,
    'PKG:002': osv.ImportFindings.INVALID_VERSION,
    'PKG:003': osv.ImportFindings.INVALID_PURL,
}

# TODO(gongh@): query the mapping from the SourceRepository database
# instead of hardcoding it.
PREFIX_TO_SOURCE = {
    'ALBA-': 'almalinux-alba',
    'ALEA-': 'almalinux-alea',
    'ALSA-': 'almalinux-alsa',
    'A-': 'android',
    'ASB-': 'android',
    'PUB-': 'android',
    'BIT-': 'bitnami',
    'CGA-': 'chainguard',
    'CURL-': 'curl',
    'CVE-': 'cve-osv',
    'DLA-': 'debian-dla',
    'DSA-': 'debian-dsa',
    'DTSA-': 'debian-dtsa',
    'GHSA-': 'ghsa',
    'GO-': 'go',
    'HSEC-': 'haskell',
    'MGASA-': 'mageia',
    'MAL-': 'malicious-packages',
    'MINI-': 'minimos',
    'OSV-': 'test-oss-fuzz',
    'PSF-': 'psf',
    'PYSEC-': 'python',
    'RSEC-': 'r',
    'RHBA-': 'redhat',
    'RHEA-': 'redhat',
    'RHSA-': 'redhat',
    'RLSA-': 'rockylinux',
    'RXSA-': 'rockylinux-rxsa',
    'RUSTSEC-': 'rust',
    'openSUSE-': 'suse',
    'SUSE-': 'suse',
    'UBUNTU-': 'ubuntu-cve',
    'LSN-': 'ubuntu-lsn',
    'USN-': 'ubuntu-usn',
    'GSD-': 'uvi',
    'V8-': 'V8',
}


def download_file(source: str, destination: str):
  """Downloads the required file from bucket."""
  storage_client = storage.Client()
  bucket = storage_client.get_bucket(VULN_BUCKET)
  try:
    blob = bucket.blob(source)
    blob.download_to_filename(destination)
  except Exception as e:
    logging.exception('Failed to download %s: %s', source, e)
    sys.exit(1)
  logging.info('Downloaded to %s.', destination)


def download_osv_data(tmp_dir: str):
  """download osv data from all.zip to a temp directory"""
  logging.info('Starts to download %s from bucket %s.', ZIP_FILE_PATH,
               VULN_BUCKET)
  all_zip = os.path.join(tmp_dir, ZIP_FILE_PATH)
  download_file(ZIP_FILE_PATH, all_zip)
  logging.info('Unzipping %s into %s...', all_zip, tmp_dir)
  with zipfile.ZipFile(all_zip, 'r') as zip_ref:
    # TODO(gongh@): add json validation here.
    zip_ref.extractall(tmp_dir)
  logging.info('Successfully unzipped files to %s.', tmp_dir)


# TODO(gongh@): This function is duplicated from importer.py.
# A common version should be created in models.py
# or other files for shared usage.
def record_quality_finding(
    bug_id: str,
    source: osv.SourceRepository.name,
    maybe_new_finding: osv.ImportFindings = osv.ImportFindings.INVALID_JSON):
  """Record the quality finding about a record in Datastore."""

  # Get any current findings for this record.
  findingtimenow = utcnow()
  if existing_finding := osv.ImportFinding.get_by_id(bug_id):
    if maybe_new_finding not in existing_finding.findings:  # type: ignore
      existing_finding.findings.append(maybe_new_finding)  # type: ignore
      existing_finding.last_attempt = findingtimenow  # type: ignore
      existing_finding.put()
  else:
    osv.ImportFinding(
        bug_id=bug_id,
        source=source,
        findings=[maybe_new_finding],
        first_seen=findingtimenow,
        last_attempt=findingtimenow).put()


def parse_and_record_linter_output(json_output_str: str):
  """
  Parses the JSON output from the OSV linter and records findings.
  """
  linter_output_json = json.loads(json_output_str)
  logging.info('Successfully parsed OSV Linter JSON output.')

  total_findings = 0
  if not linter_output_json:
    logging.info('OSV Linter output was empty JSON, indicating no findings.')
    return

  for filename, findings_list in linter_output_json.items():
    bug_id = os.path.splitext(os.path.basename(filename))[0]
    findings_already_added = set()
    if findings_list:
      total_findings += len(findings_list)
      for finding in findings_list:
        code = finding.get('Code', 'UNKNOWN_CODE')
        message = finding.get('Message', 'No message provided')
        import_finding_code = ERROR_CODE_MAPPING.get(code,
                                                     osv.ImportFindings.NONE)

        # Only adds the same finding code once per bug.
        if import_finding_code in findings_already_added:
          continue
        findings_already_added.add(import_finding_code)
        prefix = bug_id.split('-')[0] + '-'
        source = PREFIX_TO_SOURCE.get(prefix, '')
        record_quality_finding(bug_id, source,
                               import_finding_code)  # type: ignore
        logging.debug('Recorded: Code=%s, Message=%s, source=%s', code, message,
                      source)

  if total_findings > 0:
    logging.info('OSV Linter found %d issues across files.', total_findings)


def main():
  """Run linter"""
  parser = argparse.ArgumentParser(description='Linter')
  parser.add_argument('--work_dir', help='Working directory', default=TEST_DATA)
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)

  with tempfile.TemporaryDirectory(dir=tmp_dir) as tmp_dir:
    download_osv_data(tmp_dir)
    try:
      command = [
          OSV_LINTER, 'record', 'check', '--json', '--collection', 'offline',
          tmp_dir
      ]
      logging.info('Executing Go linter: %s', ' '.join(command))

      result = subprocess.run(
          command, capture_output=True, text=True, check=False, timeout=600)

      parse_and_record_linter_output(result.stdout)
    except Exception as e:
      logging.error('An unexpected error occurred: %e', e)
      sys.exit(1)


if __name__ == '__main__':
  osv.logs.setup_gcp_logging('linter')
  _ndb_client = ndb.Client()
  with _ndb_client.context():
    main()
