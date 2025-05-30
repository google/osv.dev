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
from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys
from collections import defaultdict
from typing import DefaultDict, Dict, List, Set, Tuple # Added necessary types
from xml.etree.ElementTree import Element, ElementTree, SubElement # Import specific XML types

from google.cloud import ndb

import osv.models # Import for osv.models.Bug, osv.models.AliasGroup
import osv.logs # osv.logs.setup_gcp_logging

_OUTPUT_DIRECTORY = './sitemap_output'
_SITEMAPS_PREFIX = 'sitemap_'
_SITEMAP_INDEX_PATH = f'./{_SITEMAPS_PREFIX}index.xml'
_SITEMAP_URL_LIMIT = 49999

# Global NDB client, initialized in __main__
_ndb_client: ndb.Client


def epoch() -> datetime.datetime:
  return datetime.datetime.fromtimestamp(0, tz=datetime.UTC)


# Stores bug_id -> last_modified_datetime from AliasGroup
alias_to_last_modified: DefaultDict[str, datetime.datetime] = defaultdict(epoch)


def fetch_vulnerabilities_and_dates(
    ecosystem: str) -> List[Tuple[str, datetime.datetime]]:
  """Fetch vulnerabilities' id and last modified date for the given ecosystem."""
  # Query with projection to reduce data returned
  # Order by last_modified descending to potentially get newest ones first if needed later
  bugs_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query(
      osv.models.Bug.status == osv.models.BugStatus.PROCESSED, # Direct enum comparison
      osv.models.Bug.public == True,  # noqa: E712
      osv.models.Bug.ecosystem == ecosystem,
      projection=[osv.models.Bug.last_modified] # Project only last_modified
  ).order(-osv.models.Bug.last_modified) # type: ignore[operator] # NDB query order by desc

  bug_and_dates_list: List[Tuple[str, datetime.datetime]] = [] # Renamed

  current_bug: osv.models.Bug # Type hint for loop variable
  for current_bug in bugs_query:
    # key.id() should be str. last_modified should be datetime.datetime.
    # Ensure current_bug.key and current_bug.key.id() are not None.
    # NDB entities fetched from query will have keys.
    if not current_bug.key or not current_bug.key.id() or not current_bug.last_modified:
        logging.warning("Skipping bug with missing key, id, or last_modified: %s", current_bug)
        continue

    key_id: str = current_bug.key.id() # type: ignore[union-attr]
    # Get the last modified date, considering aliases as well
    # alias_to_last_modified defaultdict will provide epoch() if key_id not found
    effective_last_modified: datetime.datetime = max(current_bug.last_modified, alias_to_last_modified[key_id])
    bug_and_dates_list.append((key_id, effective_last_modified))

  return bug_and_dates_list


def osv_get_ecosystems() -> List[str]:
  """Get list of all distinct ecosystems from public, processed bugs."""
  # This includes ecosystems with only non-processed/public entries initially,
  # but fetch_vulnerabilities_and_dates will filter those out later.
  # Query for distinct ecosystem values.
  # osv.models.Bug needed
  query_obj: ndb.Query[osv.models.Bug] = osv.models.Bug.query(
      projection=[osv.models.Bug.ecosystem], distinct=True)

  # Bug.ecosystem is a repeated StringProperty, so bug.ecosystem will be a list.
  # We expect single ecosystem per entry for this sitemap logic, so take first.
  # Filter out None or empty ecosystem lists from results.
  ecosystems_list: List[str] = []
  current_bug: osv.models.Bug
  for current_bug in query_obj:
      if current_bug.ecosystem and current_bug.ecosystem[0]: # Check if list exists and first element is not empty
          ecosystems_list.append(current_bug.ecosystem[0])

  return sorted(list(set(ecosystems_list)), key=str.lower) # Deduplicate and sort


def get_sitemap_filename_for_ecosystem(ecosystem: str) -> str:
  # Sanitize ecosystem name for filename
  ecosystem_filename_part: str = ecosystem.replace(' ', '_').replace('.', '__').strip() # Renamed
  return f'./{_SITEMAPS_PREFIX}{ecosystem_filename_part}.xml'


def get_sitemap_url_for_ecosystem(ecosystem: str, base_url: str) -> str:
  ecosystem_filename_part: str = ecosystem.replace(' ', '_').replace('.', '__').strip() # Renamed
  return f'{base_url}/{_SITEMAPS_PREFIX}{ecosystem_filename_part}.xml'


def generate_sitemap_for_ecosystem(ecosystem: str,
                                   base_url: str) -> datetime.datetime:
  """
  Generate a sitemap for the given ecosystem.
  
  Returns the latest modified date of its entries.
  """
  logging.info('Generating sitemap for ecosystem "%s".', ecosystem)
  vulnerability_and_dates: List[Tuple[str, datetime.datetime]] = fetch_vulnerabilities_and_dates(ecosystem)

  if not vulnerability_and_dates:
      logging.warning('No vulnerabilities found for ecosystem "%s". Sitemap will be empty.', ecosystem)
      # Still create an empty sitemap file for consistency in the index
      # or handle this case by not generating a file and not including in index.
      # For now, let's generate an empty one.

  sitemap_filename: str = get_sitemap_filename_for_ecosystem(ecosystem) # Renamed filename

  # Create XML structure
  urlset_element: Element = Element( # Renamed urlset
      'urlset', xmlns='http://www.sitemaps.org/schemas/sitemap/0.9')

  if len(vulnerability_and_dates) > _SITEMAP_URL_LIMIT:
    logging.warning('Ecosystem "%s" has %d vulnerabilities, exceeding sitemap URL limit of %d. Truncating.',
                    ecosystem, len(vulnerability_and_dates), _SITEMAP_URL_LIMIT)

  # Process up to the limit.
  # Ensure vulnerability_and_dates is not empty before max() if that's a concern.
  latest_mod_date_for_sitemap: datetime.datetime = epoch()

  for vuln_id_str, last_modified_dt in vulnerability_and_dates[:_SITEMAP_URL_LIMIT]: # Renamed vuln_id, last_modified
    url_element: Element = SubElement(urlset_element, 'url') # Renamed url
    loc_element: Element = SubElement(url_element, 'loc') # Renamed loc
    loc_element.text = f'{base_url}/vulnerability/{vuln_id_str}'
    lastmod_element: Element = SubElement(url_element, 'lastmod') # Renamed lastmod
    lastmod_element.text = last_modified_dt.isoformat()
    if last_modified_dt > latest_mod_date_for_sitemap:
        latest_mod_date_for_sitemap = last_modified_dt


  xml_tree: ElementTree = ElementTree(urlset_element) # Renamed tree
  # Ensure directory exists before writing
  os.makedirs(os.path.dirname(sitemap_filename) or '.', exist_ok=True)
  xml_tree.write(sitemap_filename, encoding='utf-8', xml_declaration=True)

  # If vulnerability_and_dates was empty, latest_mod_date_for_sitemap is still epoch().
  return latest_mod_date_for_sitemap


def generate_sitemap_index(ecosystems_set: Set[str], # Renamed ecosystems
                           base_url: str,
                           last_mod_dict: Dict[str, datetime.datetime]) -> None:
  """Generate a sitemap index."""
  logging.info('Generating sitemap index.')
  sitemapindex_element: Element = Element( # Renamed sitemapindex
      'sitemapindex', xmlns='http://www.sitemaps.org/schemas/sitemap/0.9')

  for ecosystem_name in sorted(list(ecosystems_set)): # Process in a defined order (Renamed ecosystem)
    sitemap_element: Element = SubElement(sitemapindex_element, 'sitemap') # Renamed sitemap
    loc_element: Element = SubElement(sitemap_element, 'loc') # Renamed loc
    loc_element.text = get_sitemap_url_for_ecosystem(ecosystem_name, base_url)
    lastmod_element: Element = SubElement(sitemap_element, 'lastmod') # Renamed lastmod
    # Ensure ecosystem_name is in last_mod_dict; should be if logic is correct.
    lastmod_element.text = last_mod_dict.get(ecosystem_name, epoch()).isoformat()


  xml_tree: ElementTree = ElementTree(sitemapindex_element) # Renamed tree
  xml_tree.write(_SITEMAP_INDEX_PATH, encoding='utf-8', xml_declaration=True)


def generate_sitemaps(base_url: str) -> None:
  """Generate sitemaps including all vulnerabilities, split by ecosystem."""
  logging.info("Begin generating sitemaps.")
  # Filter for base ecosystems (e.g., "Go" from "Go:modules") to avoid duplication.
  # The sitemap for "Go" should ideally include all "Go:*" vulnerabilities.
  # The current fetch_vulnerabilities_and_dates might need adjustment if it strictly matches ecosystem.
  # Assuming osv_get_ecosystems() provides all variants, and we filter for base ones.
  all_ecosystems: List[str] = osv_get_ecosystems()
  base_ecosystems_set: Set[str] = { # Renamed base_ecosystems
      eco for eco in all_ecosystems if ':' not in eco # Simple definition of a "base" ecosystem
  }
  # Also include specific prefixed ecosystems if they are substantial and not covered by base.
  # For now, this logic is simple. This might need refinement based on how ecosystems are structured.

  ecosystem_last_mod_dates: Dict[str, datetime.datetime] = {}
  for ecosystem_name in base_ecosystems_set: # Renamed ecosystem
    ecosystem_last_mod_dates[ecosystem_name] = generate_sitemap_for_ecosystem(
        ecosystem_name, base_url)

  generate_sitemap_index(base_ecosystems_set, base_url, ecosystem_last_mod_dates)
  logging.info("Sitemap generation complete.")


def preload_alias_groups() -> None:
  """Fetch all alias groups and populate alias_to_last_modified map."""
  logging.info("Preloading alias groups into memory.")
  # osv.models.AliasGroup needed
  alias_groups_query: ndb.Query[osv.models.AliasGroup] = osv.models.AliasGroup.query() # Renamed aliases

  alias_group_item: osv.models.AliasGroup # Type hint for loop variable, renamed al
  for alias_group_item in alias_groups_query:
    # Ensure bug_ids and last_modified are not None
    if not alias_group_item.bug_ids or not alias_group_item.last_modified:
        continue
    for bug_id_str in alias_group_item.bug_ids: # Renamed bug_id
      if bug_id_str: # Ensure bug_id_str is not empty
          # Update if current group's last_modified is newer
          if alias_group_item.last_modified > alias_to_last_modified[bug_id_str]:
              alias_to_last_modified[bug_id_str] = alias_group_item.last_modified
  logging.info("Finished preloading %d alias modification times.", len(alias_to_last_modified))


def main() -> int:
  parser = argparse.ArgumentParser(description='Generate sitemaps.')
  parser.add_argument(
      '--base_url',
      type=str, # Ensure type is str
      required=True,
      help='The base URL for the sitemap entries (without trailing /).')
  args = parser.parse_args()

  os.makedirs(_OUTPUT_DIRECTORY, exist_ok=True)
  os.chdir(_OUTPUT_DIRECTORY) # Changes current working directory. Paths should be relative to this.

  preload_alias_groups()
  generate_sitemaps(args.base_url)
  logging.info("Sitemaps generated successfully in %s", os.getcwd())
  return 0


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('generate_sitemap') # project_id inferred
  with _ndb_client.context():
    sys.exit(main())
