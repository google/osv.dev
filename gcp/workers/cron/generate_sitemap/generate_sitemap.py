#!/usr/bin/env python3

# Copyright 2024 Google LLC
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
"""Generate sitemap."""
import logging
import sys
import os
import osv
import osv.logs
import datetime
import argparse
from collections import defaultdict
from google.cloud import ndb

from xml.etree.ElementTree import Element, SubElement, ElementTree

_OUTPUT_DIRECTORY = './sitemap_output'
_SITEMAPS_PREFIX = 'sitemap_'
_SITEMAP_INDEX_PATH = f'./{_SITEMAPS_PREFIX}index.xml'
_SITEMAP_URL_LIMIT = 49999


def epoch() -> datetime.datetime:
  return datetime.datetime.fromtimestamp(0).astimezone(datetime.UTC)


alias_to_last_modified: defaultdict[str, datetime.datetime] = defaultdict(epoch)


def fetch_vulnerabilities_and_dates(
    ecosystem: str) -> list[tuple[str, datetime.datetime]]:
  """Fetch vulnerabilities' id for the given ecosystem."""
  # Query with projection to reduce data returned
  # Order does not matter, other than to keep things consistent
  bugs = osv.Bug.query(
      osv.Bug.status == osv.BugStatus.PROCESSED,
      osv.Bug.public == True,  # pylint: disable=singleton-comparison
      osv.Bug.ecosystem == ecosystem,
      projection=[osv.Bug.last_modified]).order(-osv.Bug.last_modified)

  bug_and_dates = []
  for bug in bugs:
    key = bug.key.id()
    # Make sure to set the timezone to UTC to add +00:00 when outputting iso
    last_mod_date = max(
        bug.last_modified.replace(tzinfo=datetime.UTC),
        alias_to_last_modified[bug.key.id()])
    bug_and_dates.append((key, last_mod_date))

  return bug_and_dates


def osv_get_ecosystems():
  """Get list of ecosystems."""
  # This includes ecosystems with only non processed/public entries
  query = osv.Bug.query(projection=[osv.Bug.ecosystem], distinct=True)
  return sorted([bug.ecosystem[0] for bug in query if bug.ecosystem],
                key=str.lower)


def get_sitemap_filename_for_ecosystem(ecosystem: str) -> str:
  ecosystem_name = ecosystem.replace(' ', '_').replace('.', '__').strip()
  return f'./{_SITEMAPS_PREFIX}{ecosystem_name}.xml'


def get_sitemap_url_for_ecosystem(ecosystem: str, base_url: str) -> str:
  ecosystem_name = ecosystem.replace(' ', '_').replace('.', '__').strip()
  return f'{base_url}/{_SITEMAPS_PREFIX}{ecosystem_name}.xml'


def generate_sitemap_for_ecosystem(ecosystem: str,
                                   base_url: str) -> datetime.datetime:
  """
  Generate a sitemap for the give n ecosystem.
  
  Returns the latest modified date of it's entries.
  """
  logging.info('Generating sitemap for ecosystem "%s".', ecosystem)
  vulnerability_and_dates = fetch_vulnerabilities_and_dates(ecosystem)
  filename = get_sitemap_filename_for_ecosystem(ecosystem)
  urlset = Element(
      'urlset', xmlns='http://www.sitemaps.org/schemas/sitemap/0.9')

  if len(vulnerability_and_dates) > _SITEMAP_URL_LIMIT:
    logging.warning('Ecosystem "%s" Exceeded sitemap size limit', ecosystem)

  # TODO: For large ecosystems with over 50,000 vulnerabilities, generate
  # multiple sitemaps.
  for vuln_id, last_modified in vulnerability_and_dates[:_SITEMAP_URL_LIMIT]:
    url = SubElement(urlset, 'url')
    loc = SubElement(url, 'loc')
    loc.text = f'{base_url}/vulnerability/{vuln_id}'
    lastmod = SubElement(url, 'lastmod')
    lastmod.text = last_modified.isoformat()

  tree = ElementTree(urlset)
  tree.write(filename, encoding='utf-8', xml_declaration=True)

  # Addition of epoch for edge cases where vulnerability is empty
  return max([
      last_mod for _, last_mod in vulnerability_and_dates[:_SITEMAP_URL_LIMIT]
  ] + [epoch()])


def generate_sitemap_index(ecosystems: set[str], base_url: str,
                           last_mod_dict: dict[str, datetime.datetime]) -> None:
  """Generate a sitemap index."""
  logging.info('Generating sitemap index.')
  sitemapindex = Element(
      'sitemapindex', xmlns='http://www.sitemaps.org/schemas/sitemap/0.9')

  for ecosystem in ecosystems:
    sitemap = SubElement(sitemapindex, 'sitemap')
    loc = SubElement(sitemap, 'loc')
    loc.text = get_sitemap_url_for_ecosystem(ecosystem, base_url)
    lastmod = SubElement(sitemap, 'lastmod')
    lastmod.text = last_mod_dict[ecosystem].isoformat()

  tree = ElementTree(sitemapindex)
  tree.write(_SITEMAP_INDEX_PATH, encoding='utf-8', xml_declaration=True)


def generate_sitemaps(base_url: str) -> None:
  """Generate sitemaps including all vulnerabilities, split by ecosystem."""
  logging.info("Begin generating sitemaps.")
  # Go over the base ecosystems index. Otherwise we'll have duplicated
  # vulnerabilities in the sitemap.
  base_ecosystems = {
      ecosystem for ecosystem in osv_get_ecosystems() if ':' not in ecosystem
  }

  ecosystem_last_mod_dates = {}
  for ecosystem in base_ecosystems:
    ecosystem_last_mod_dates[ecosystem] = generate_sitemap_for_ecosystem(
        ecosystem, base_url)

  generate_sitemap_index(base_ecosystems, base_url, ecosystem_last_mod_dates)


def preload_alias_groups():
  """Fetch all alias groups, as we will be querying all of them anyway"""
  logging.info("Preloading alias groups into memory.")
  aliases = osv.AliasGroup.query()
  for al in aliases:
    al: osv.AliasGroup
    for bug_id in al.bug_ids:  # type: ignore
      alias_to_last_modified[bug_id] = al.last_modified.replace(  # type: ignore
          tzinfo=datetime.UTC)


def main() -> int:
  parser = argparse.ArgumentParser(description='Generate sitemaps.')
  parser.add_argument(
      '--base_url',
      required=True,
      help='The base URL for the sitemap entries (without trailing /).')
  args = parser.parse_args()

  os.makedirs(_OUTPUT_DIRECTORY, exist_ok=True)
  os.chdir(_OUTPUT_DIRECTORY)

  preload_alias_groups()
  generate_sitemaps(args.base_url)
  return 0


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('generate_sitemap')
  with _ndb_client.context():
    sys.exit(main())
