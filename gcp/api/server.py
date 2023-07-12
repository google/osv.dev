# Copyright 2021 Google LLC
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
"""OSV API server implementation."""

import argparse
import codecs
import concurrent
from dataclasses import dataclass
import math
import hashlib
import functools
import logging
import os
import time
from typing import Callable, List

from collections import defaultdict

from google.cloud import ndb
from google.api_core.exceptions import InvalidArgument
import google.cloud.ndb.exceptions as ndb_exceptions

import grpc
from grpc_health.v1 import health_pb2
from grpc_health.v1 import health_pb2_grpc
from grpc_reflection.v1alpha import reflection
from packageurl import PackageURL

import osv
from osv import ecosystems
from osv import semver_index
from osv import purl_helpers
from osv.logs import setup_gcp_logging
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

_SHUTDOWN_GRACE_DURATION = 5

_MAX_BATCH_QUERY = 1000
# Maximum number of responses to return before applying post exceeded limit
_MAX_VULN_RESP_THRESH = 3000
# Max responses after MAX_VULN_RESP_THRESH has been exceeded
_MAX_VULN_LISTED_POST_EXCEEDED = 5
# Max responses before MAX_VULN_RESP_THRESH has been exceeded
_MAX_VULN_LISTED_PRE_EXCEEDED = 1000

# Used in DetermineVersion
# If there are more results for a bucket than this number,
# ignore the bucket completely
_MAX_MATCHES_TO_CARE = 100
# Max results to return for DetermineVersion
_MAX_DETERMINE_VER_RESULTS_TO_RETURN = 10
_DETERMINE_VER_MIN_SCORE_CUTOFF = 0.05
# Size of buckets to divide hashes into in DetermineVersion
# This should match the number in the indexer
_BUCKET_SIZE = 512

# Prefix for the
_TAG_PREFIX = "refs/tags/"

_ndb_client = ndb.Client()

_LINUX_ERROR = ("Linux Kernel queries are currently unavailable: " +
                "See https://google.github.io/osv.dev/faq/" +
                "#why-am-i-getting-an-error-message-for-my-linux-kernel-query")


def ndb_context(func):
  """Wrapper to create an NDB context."""

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    with _ndb_client.context():
      return func(*args, **kwargs)

  return wrapper


class OSVServicer(osv_service_v1_pb2_grpc.OSVServicer,
                  health_pb2_grpc.HealthServicer):
  """V1 OSV servicer."""

  @ndb_context
  def GetVulnById(self, request, context: grpc.ServicerContext):
    """Return a `Vulnerability` object for a given OSV ID."""
    bug: osv.Bug = osv.Bug.get_by_id(request.id)
    if not bug or bug.status == osv.BugStatus.UNPROCESSED:
      context.abort(grpc.StatusCode.NOT_FOUND, 'Bug not found.')
      return None

    if not bug.public:
      context.abort(grpc.StatusCode.PERMISSION_DENIED, 'Permission denied.')
      return None

    return bug_to_response(bug)

  @ndb_context
  def QueryAffected(self, request, context: grpc.ServicerContext):
    """Query vulnerabilities for a particular project at a given commit or

    version.
    """
    page_token = None
    if request.query.page_token:
      try:
        page_token = ndb.Cursor(urlsafe=request.query.page_token)
      except ValueError as e:
        logging.warning(e)
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid page token.')

    query_context = QueryContext(
        service_context=context,
        # request_start_time=datetime.now(),
        page_token=page_token,
        total_responses=ResponsesCount(0))

    try:
      results, next_page_token = do_query(request.query, query_context).result()
    except InvalidArgument:
      # Currently cannot think of any other way
      # this can be raised other than invalid cursor
      context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    'Invalid query, likely caused by invalid page token.')
    except ndb_exceptions.BadValueError as e:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    f'Bad parameter value: {e}')

    if results is not None:
      return osv_service_v1_pb2.VulnerabilityList(
          vulns=results, next_page_token=next_page_token)

    return None

  @ndb_context
  def QueryAffectedBatch(self, request, context: grpc.ServicerContext):
    """Query vulnerabilities (batch)."""
    batch_results = []
    futures = []

    if len(request.query.queries) > _MAX_BATCH_QUERY:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Too many queries.')
      return None

    total_responses = ResponsesCount(0)
    # req_start_time = datetime.now()
    for i, query in enumerate(request.query.queries):
      page_token = None
      if query.page_token:
        try:
          page_token = ndb.Cursor(urlsafe=query.page_token)
        except ValueError as e:
          logging.warning(e)
          context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                        f'Invalid page token at index: {i}.')
      query_context = QueryContext(
          service_context=context,
          # request_start_time=req_start_time,
          page_token=page_token,
          total_responses=total_responses)

      futures.append(do_query(query, query_context, include_details=False))

    for future in futures:
      try:
        result, next_page_token = future.result()
      except InvalidArgument:
        # Currently cannot think of any other way
        # this can be raised other than invalid cursor
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                      'Invalid query, likely caused by invalid page token.')
      except ndb_exceptions.BadValueError as e:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                      f'Bad parameter value: {e}')

      batch_results.append(
          osv_service_v1_pb2.VulnerabilityList(
              vulns=result, next_page_token=next_page_token))

    return osv_service_v1_pb2.BatchVulnerabilityList(results=batch_results)

  @ndb_context
  def DetermineVersion(self, request, context: grpc.ServicerContext):
    """Determine the version of the provided hashes."""
    res = determine_version(request.query, context).result()
    return res

  @ndb_context
  def Check(self, request, context: grpc.ServicerContext):
    """Health check per the gRPC health check protocol."""
    del request  # Unused.
    del context  # Unused.

    # Read up to a single Bug entity from the DB. This should not cause an
    # exception or time out.
    osv.Bug.query().fetch(1)
    return health_pb2.HealthCheckResponse(
        status=health_pb2.HealthCheckResponse.ServingStatus.SERVING)

  def Watch(self, request, context: grpc.ServicerContext):
    """Health check per the gRPC health check protocol."""
    del request  # Unused.
    context.abort(grpc.StatusCode.UNIMPLEMENTED, "Unimplemented")


# Wrapped in a separate class
@dataclass
class ResponsesCount:
  """Wraps responses count in a separate class 
  to allow it to be passed by reference
  
  Also adds a interface to allow easy updating to a mutex
  if necessary
  """
  count: int

  def add(self, amount):
    # This is to prevent query `limit` parameter being smaller than
    # the number that is checked later in the iter() loop for the last page
    if amount < 0:
      raise ValueError("change amount must be positive")
    self.count += amount

  def exceeded(self) -> bool:
    return self.count > _MAX_VULN_RESP_THRESH

  def page_limit(self) -> int:
    """
    Returns the limit based on whether we have 
    exceeded the _MAX_VULN_RESP_THRESH with the total number
    of responses in the entire query batch
    """
    if self.exceeded():
      return _MAX_VULN_LISTED_POST_EXCEEDED

    return _MAX_VULN_LISTED_PRE_EXCEEDED


@dataclass
class QueryContext:
  service_context: grpc.ServicerContext
  page_token: ndb.Cursor | None
  # request_start_time: datetime
  # Use a dataclass to copy by reference
  total_responses: ResponsesCount


def process_buckets(
    file_results: List[osv.FileResult]) -> List[osv.RepoIndexBucket]:
  """
  Create buckets in the same process as 
  indexer to generate the same bucket hashes
  """
  buckets: list[list[bytes]] = [[] for _ in range(_BUCKET_SIZE)]

  for fr in file_results:
    buckets[int.from_bytes(fr.hash[:2], byteorder='big') % _BUCKET_SIZE].append(
        fr.hash)

  results: list[osv.RepoIndexBucket] = [None] * _BUCKET_SIZE
  for bucket_idx, bucket in enumerate(buckets):
    bucket.sort()

    hasher = hashlib.md5()
    for v in bucket:
      hasher.update(v)

    results[bucket_idx] = osv.RepoIndexBucket(
        node_hash=hasher.digest(),
        files_contained=len(bucket),
    )

  return results


def build_determine_version_result(
    file_matches_by_proj: dict[ndb.Key, int],
    bucket_matches_by_proj: dict[ndb.Key, int],
    num_skipped_buckets: int,
    # 1 means has items, 0 means empty
    empty_bucket_bitmap: int,
    query_file_count: int) -> osv_service_v1_pb2.VersionMatchList:
  """Build sorted determine version result from the input"""
  bucket_match_items = list(bucket_matches_by_proj.items())
  # Sort by number of files matched
  bucket_match_items.sort(key=lambda x: x[1], reverse=True)

  # Only interested in our maximum number of results
  bucket_match_items = bucket_match_items[:min(
      _MAX_DETERMINE_VER_RESULTS_TO_RETURN, len(bucket_match_items))]
  idx_futures = ndb.get_multi_async([b[0] for b in bucket_match_items])
  output = []

  # Apply bitwise NOT to the user bitmap
  inverted_empty_bucket_bitmap = (1 << _BUCKET_SIZE) - 1 - empty_bucket_bitmap
  empty_bucket_count = inverted_empty_bucket_bitmap.bit_count()

  for i, f in enumerate(idx_futures):
    idx: osv.RepoIndex = f.result()

    if idx is None:
      logging.warning(
          'Bucket exists for project: %s, which does ' +
          'not have a matching IndexRepo entry', bucket_match_items[i][0])
      continue

    if idx.empty_bucket_bitmap is None:
      logging.warning('No empty bucket bitmap for: %s@%s', idx.name, idx.tag)
      continue

    # Byte order little is how the bitmap is stored in the indexer originally
    bitmap = int.from_bytes(idx.empty_bucket_bitmap, byteorder='little')

    # We are looking to find cases where the bitmap generated by the user query
    # gives a 0, but the bitmap of the repo is a 1.
    # We do not want to count cases where the repo bitmap contains 0 but
    # the user bitmap contains 1, since these are already accounted for by not
    # having these in the query results in the first place.
    # A bitwise NOT on the user query bitmap followed by a bitwise AND satisfies
    # this requirement.
    missed_empty_buckets = (inverted_empty_bucket_bitmap & bitmap).bit_count()

    estimated_diff_files = estimate_diff(
        _BUCKET_SIZE  # Starting with the total number of buckets
        - bucket_matches_by_proj[idx.key]  # Buckets that match are not changed
        - empty_bucket_count  # Buckets that are empty are not changed
        + missed_empty_buckets  # Unless they don't match the bitmap
        - num_skipped_buckets,  # Buckets skipped are assumed unchanged
        abs(idx.file_count - query_file_count)  # The difference in file count
    )

    max_files = max(idx.file_count, query_file_count)

    version = osv.normalize_tag(idx.tag.removeprefix(_TAG_PREFIX))
    version = version.replace('-', '.')
    if not version:  # This tag actually isn't a version (rare)
      continue

    version_match = osv_service_v1_pb2.VersionMatch(
        score=(max_files - estimated_diff_files) / max_files,
        minimum_file_matches=file_matches_by_proj[idx.key],
        estimated_diff_files=estimated_diff_files,
        repo_info=osv_service_v1_pb2.VersionRepositoryInformation(
            type=osv_service_v1_pb2.VersionRepositoryInformation.GIT,
            address=idx.repo_addr,
            commit=idx.commit.hex(),
            tag=idx.tag.removeprefix(_TAG_PREFIX),
            version=version,
        ))

    if version_match.score < _DETERMINE_VER_MIN_SCORE_CUTOFF:
      continue

    output.append(version_match)

  output.sort(key=lambda x: x.score, reverse=True)

  return osv_service_v1_pb2.VersionMatchList(matches=output)


def estimate_diff(num_bucket_change: int, file_count_diff: int) -> int:
  """
  Estimates the number of files that have changed based on 
  the number of buckets that changed.
  """
  estimate = _BUCKET_SIZE * math.log(
      (_BUCKET_SIZE + 1) / (_BUCKET_SIZE - num_bucket_change + 1))

  return file_count_diff + round(max(estimate - file_count_diff, 0) / 2)


@ndb.tasklet
def determine_version(version_query: osv_service_v1_pb2.VersionQuery,
                      _: grpc.ServicerContext) -> ndb.Future:
  """Identify fitting commits based on a subset of hashes"""
  req_list = [osv.FileResult(hash=x.hash) for x in version_query.file_hashes]

  # Build all the buckets and query the bucket hash
  buckets = process_buckets(req_list)

  file_match_count: dict[ndb.Key, int] = defaultdict(int)
  bucket_match_count: dict[ndb.Key, int] = defaultdict(int)
  num_skipped_buckets = 0
  skipped_files = 0

  # 1 means not empty, 0 means empty
  empty_bucket_bitmap = 0

  # Tuple is (Future, index, number_of_files)
  query_futures: list[tuple[ndb.Future, int, int]] = []

  for idx, bucket in enumerate(buckets):
    if bucket.files_contained == 0:
      continue

    empty_bucket_bitmap |= 1 << idx
    query = osv.RepoIndexBucket.query(
        osv.RepoIndexBucket.node_hash == bucket.node_hash)
    # Limit the number of requests to prevent super long queries
    query_futures.append((query.fetch_async(limit=_MAX_MATCHES_TO_CARE), idx,
                          bucket.files_contained))

  # Take the results and group the library versions,
  # aggregating on the number of files matched

  for future, idx, num_of_files in query_futures:
    result: list[osv.RepoIndexBucket] = list(future.result())
    if result:  # If there is a match, add it to list of potential versions
      # If it equals the limit, there probably is more versions beyond the limit
      # so just ignore it completely since it's not a useful indicator
      if len(result) == _MAX_MATCHES_TO_CARE:
        num_skipped_buckets += 1
        skipped_files += num_of_files
        continue

      for index_bucket in result:
        parent_key = index_bucket.key.parent()
        file_match_count[parent_key] += index_bucket.files_contained
        bucket_match_count[parent_key] += 1

  # Up the matches by the ones that match too commonly
  # This is used to return 100% matches
  for key in file_match_count.keys():
    file_match_count[key] += skipped_files

  return build_determine_version_result(file_match_count, bucket_match_count,
                                        num_skipped_buckets,
                                        empty_bucket_bitmap,
                                        len(version_query.file_hashes))


@ndb.tasklet
def do_query(query, context: QueryContext, include_details=True):
  """Do a query."""
  if query.HasField('package'):
    package_name = query.package.name
    ecosystem = query.package.ecosystem
    purl_str = query.package.purl
  else:
    package_name = ''
    ecosystem = ''
    purl_str = ''

  # TODO: Remove this after paging is implemented
  if package_name == "Kernel" and (not ecosystem or ecosystem == "Linux"):
    context.service_context.abort(grpc.StatusCode.UNAVAILABLE, _LINUX_ERROR)

  purl = None
  purl_version = None
  if purl_str:
    try:
      parsed_purl = PackageURL.from_string(purl_str)
      purl_version = parsed_purl.version
      purl = parsed_purl
    except ValueError:
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                    'Invalid Package URL.')

  def to_response(b):
    return bug_to_response(b, include_details)

  next_page_token = None

  if query.WhichOneof('param') == 'commit':
    try:
      commit_bytes = codecs.decode(query.commit, 'hex')
    except ValueError:
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                    'Invalid hash.')
      return None

    bugs, next_page_token = yield query_by_commit(
        context, commit_bytes, to_response=to_response)
  elif purl and purl_version:
    bugs, next_page_token = yield query_by_version(
        context,
        package_name,
        ecosystem,
        purl,
        purl_version,
        to_response=to_response)
  elif query.WhichOneof('param') == 'version':
    bugs, next_page_token = yield query_by_version(
        context,
        package_name,
        ecosystem,
        purl,
        query.version,
        to_response=to_response)
  elif (package_name != '' and ecosystem != '') or (purl and not purl_version):
    # Package specified without version.
    bugs, next_page_token = yield query_by_package(
        context, package_name, ecosystem, purl, to_response=to_response)
  else:
    context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                  'Invalid query.')

  if next_page_token:
    next_page_token = next_page_token.urlsafe()
    logging.warning('Page size limit hit, response size: %s', len(bugs))

  return bugs, next_page_token


def bug_to_response(bug, include_details=True):
  """Convert a Bug entity to a response object."""
  if include_details:
    return bug.to_vulnerability(include_source=True)

  return bug.to_vulnerability_minimal()


@ndb.tasklet
def _get_bugs(bug_ids, to_response=bug_to_response):
  """Get bugs from bug ids."""
  bugs = ndb.get_multi_async([ndb.Key(osv.Bug, bug_id) for bug_id in bug_ids])

  responses = []
  for future_bug in bugs:
    bug: osv.Bug = yield future_bug
    if bug and bug.status == osv.BugStatus.PROCESSED and bug.public:
      responses.append(to_response(bug))

  return responses


def _datastore_normalized_purl(purl: PackageURL):
  """
  Returns a new PURL with most attributes removed, used for datastore queries
  """
  values = purl.to_dict()
  values.pop('version', None)
  values.pop('subpath', None)
  values.pop('qualifiers', None)
  return PackageURL(**values)


@ndb.tasklet
def query_by_commit(
    context: QueryContext,
    commit: bytes,
    to_response: Callable = bug_to_response) -> tuple[list, ndb.Cursor]:
  """Query by commit."""
  query = osv.AffectedCommits.query(osv.AffectedCommits.commits == commit)

  gsd_count = 0
  bug_ids = []
  it: ndb.QueryIterator = query.iter(
      keys_only=True, start_cursor=context.page_token)

  cursor = None
  while (yield it.has_next_async()):
    if len(bug_ids) >= context.total_responses.page_limit():
      cursor = it.cursor_after()
      break

    # Affect commits key follows this format:
    # <BugID>-<PageNumber>
    affected_commits: ndb.Key = it.next()
    bug_id: str = affected_commits.id().rsplit("-", 1)[0]

    # Temporary mitigation.
    if bug_id.startswith('GSD-'):
      gsd_count += 1
      if gsd_count >= 10:
        context.service_context.abort(grpc.StatusCode.UNAVAILABLE, _LINUX_ERROR)

      continue

    bug_ids.append(bug_id)
    context.total_responses.add(1)

  bugs = yield _get_bugs(bug_ids, to_response=to_response)
  return bugs, cursor


def _match_purl(purl_query: PackageURL, purl_db: PackageURL) -> bool:
  """Check if purl match at the specifity level of purl_query

  If purl_query doesn't have qualifiers, then we will match against purl_db
  without qualifiers, otherwise match with qualifiers
  """

  # Define _clean_purl inside to make sure it's only used within _match_purl
  def _clean_purl(purl: PackageURL):
    """
    Clean a purl object for matching

    Removes version, subpath, and qualifiers with the exception of
    the 'arch' qualifier
    """
    values = purl.to_dict()
    values.pop('version', None)
    values.pop('subpath', None)
    qualifiers = values.pop('qualifiers', None)
    new_qualifiers = {}
    if qualifiers and 'arch' in qualifiers:  # CPU arch for debian packages
      new_qualifiers['arch'] = qualifiers['arch']
    return PackageURL(qualifiers=new_qualifiers, **values)

  purl_query = _clean_purl(purl_query)
  # Most of the time this will have no effect, since PURLs in the db
  # are already cleaned
  purl_db = _clean_purl(purl_db)
  if not purl_query.qualifiers:
    # No qualifiers, and our PURLs never have versions, so just match name
    return purl_query.name == purl_db.name

  if purl_db.qualifiers:
    # A arch of 'source' matches all other architectures
    if purl_db.qualifiers['arch'] == 'source':
      purl_db.qualifiers['arch'] = purl_query.qualifiers['arch']

  return purl_query == purl_db


def _is_semver_affected(affected_packages, package_name, ecosystem,
                        purl: PackageURL | None, version):
  """Returns whether or not the given version is within an affected SEMVER

  range.
  """
  version = semver_index.parse(version)

  affected = False
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem and ecosystem != affected_package.package.ecosystem:
      continue

    if purl and not (affected_package.package.purl and _match_purl(
        purl, PackageURL.from_string(affected_package.package.purl))):
      continue

    for affected_range in affected_package.ranges:
      if affected_range.type != 'SEMVER':
        continue

      for event in osv.sorted_events('', affected_range.type,
                                     affected_range.events):
        if (event.type == 'introduced' and
            (event.value == '0' or version >= semver_index.parse(event.value))):
          affected = True

        if event.type == 'fixed' and version >= semver_index.parse(event.value):
          affected = False

        if event.type == 'last_affected' and version > semver_index.parse(
            event.value):
          affected = False

      if affected:
        return affected

  return affected


def _is_version_affected(affected_packages,
                         package_name,
                         ecosystem,
                         purl: PackageURL | None,
                         version,
                         normalize=False):
  """Returns whether or not the given version is within an affected ECOSYSTEM

  range.
  """
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem:
      # If package ecosystem has a :, also try ignoring parts after it.
      if (affected_package.package.ecosystem != ecosystem and
          ecosystems.normalize(
              affected_package.package.ecosystem) != ecosystem):
        continue

    if purl and not (affected_package.package.purl and _match_purl(
        purl, PackageURL.from_string(affected_package.package.purl))):
      continue

    if normalize:
      if any(
          osv.normalize_tag(version) == osv.normalize_tag(v)
          for v in affected_package.versions):
        return True
    else:
      if version in affected_package.versions:
        return True

  return False


@ndb.tasklet
def _query_by_semver(context: QueryContext, query: ndb.Query, package_name: str,
                     ecosystem: str, purl: PackageURL | None, version: str):
  """Query by semver."""
  if not semver_index.is_valid(version):
    return [], None

  results = []
  query = query.filter(
      osv.Bug.semver_fixed_indexes > semver_index.normalize(version))
  it: ndb.QueryIterator = query.iter(start_cursor=context.page_token)
  cursor = None

  while (yield it.has_next_async()):
    if len(results) >= context.total_responses.page_limit():
      cursor = it.cursor_after()
      break

    bug: osv.Bug = it.next()  # type: ignore
    if _is_semver_affected(bug.affected_packages, package_name, ecosystem, purl,
                           version):
      results.append(bug)
      context.total_responses.add(1)

  return results, cursor


@ndb.tasklet
def _query_by_generic_version(
    context: QueryContext,
    base_query: ndb.Query,
    project: str,
    ecosystem: str,
    purl: PackageURL | None,
    version: str,
):
  """Query by generic version."""
  # Try without normalizing.
  results = []
  query: ndb.Query = base_query.filter(osv.Bug.affected_fuzzy == version)
  it: ndb.QueryIterator = query.iter(
      # page_token can be the token for this query, or the token for the one
      # below. If the token is used for the normalized query below, this query
      # must have returned no results, so will still return no results, fall
      # through to the query below again.
      start_cursor=context.page_token)
  cursor = None

  while (yield it.has_next_async()):
    if len(results) >= context.total_responses.page_limit():
      cursor = it.cursor_after()
      break
    bug = it.next()
    if _is_version_affected(bug.affected_packages, project, ecosystem, purl,
                            version):
      results.append(bug)
      context.total_responses.add(1)

  if results:
    return results, cursor

  # Try again after normalizing.
  version = osv.normalize_tag(version)
  query = base_query.filter(osv.Bug.affected_fuzzy == version)
  it = query.iter(start_cursor=context.page_token)

  while (yield it.has_next_async()):
    if len(results) >= context.total_responses.page_limit():
      cursor = it.cursor_after()
      break

    bug = it.next()
    if _is_version_affected(
        bug.affected_packages,
        project,
        ecosystem,
        purl,
        version,
        normalize=True):
      results.append(bug)
      context.total_responses.add(1)

  return results, cursor


@ndb.tasklet
def query_by_version(context: QueryContext,
                     package_name: str,
                     ecosystem: str,
                     purl: PackageURL | None,
                     version,
                     to_response: Callable = bug_to_response):
  """Query by (fuzzy) version."""

  if package_name:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.project == package_name,
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  elif purl:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.purl == _datastore_normalized_purl(purl).to_string(),
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  else:
    return [], None

  if ecosystem:
    query = query.filter(osv.Bug.ecosystem == ecosystem)

  if purl:
    if ecosystem:  # Purl's already include the ecosystem inside
      context.service_context.abort(
          grpc.StatusCode.INVALID_ARGUMENT,
          'Ecosystem specified in a purl query',
      )

    purl_ecosystem = purl_helpers.purl_to_ecosystem(purl.type)
    if purl_ecosystem:
      ecosystem = purl_ecosystem

  ecosystem_info = ecosystems.get(ecosystem)
  is_semver = ecosystem_info and ecosystem_info.is_semver

  bugs = []
  next_page_token = None
  if ecosystem:
    if is_semver:
      # Ecosystem supports semver only.
      bugs, next_page_token = yield _query_by_semver(context, query,
                                                     package_name, ecosystem,
                                                     purl, version)
    else:
      bugs, next_page_token = yield _query_by_generic_version(
          context, query, package_name, ecosystem, purl, version)
  else:
    logging.warning("Package query without ecosystem specified")
    # Unspecified ecosystem. Try both.

    # TODO: Remove after testing how many consumers are
    # querying the API this way.
    context.page_token = None
    new_bugs, _ = yield _query_by_semver(context, query, package_name,
                                         ecosystem, purl, version)
    bugs.extend(new_bugs)
    new_bugs, _ = yield _query_by_generic_version(context, query, package_name,
                                                  ecosystem, purl, version)
    bugs.extend(new_bugs)

    # Trying both is too difficult/ugly with paging
    # Our documentation states that this is an invalid query
    # context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
    #                               'Ecosystem not specified')

  return [to_response(bug) for bug in bugs], next_page_token


@ndb.tasklet
def query_by_package(context: QueryContext, package_name: str, ecosystem: str,
                     purl: PackageURL | None,
                     to_response: Callable) -> tuple[list, ndb.Cursor]:
  """Query by package."""
  bugs = []
  if package_name and ecosystem:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.project == package_name,
        osv.Bug.ecosystem == ecosystem,
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  elif purl:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.purl == _datastore_normalized_purl(purl).to_string(),
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  else:
    return [], None

  it: ndb.QueryIterator = query.iter(start_cursor=context.page_token)
  cursor = None
  while (yield it.has_next_async()):
    if len(bugs) >= context.total_responses.page_limit():
      cursor = it.cursor_after()
      break

    bug: osv.Bug = it.next()

    if purl:
      affected = False
      # Check if any affected packages actually match _match_purl
      for affected_package in bug.affected_packages:
        affected_package: osv.AffectedPackage
        if not (affected_package.package.purl and _match_purl(
            purl, PackageURL.from_string(affected_package.package.purl))):
          continue

        affected = True
        break
    else:
      affected = True

    if affected:
      bugs.append(bug)
      context.total_responses.add(1)

  return [to_response(bug) for bug in bugs], cursor


def serve(port: int, local: bool):
  """Configures and runs the OSV API server."""
  server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
  servicer = OSVServicer()
  osv_service_v1_pb2_grpc.add_OSVServicer_to_server(servicer, server)
  health_pb2_grpc.add_HealthServicer_to_server(servicer, server)
  if local:
    service_names = (
        osv_service_v1_pb2.DESCRIPTOR.services_by_name['OSV'].full_name,
        health_pb2.DESCRIPTOR.services_by_name['Health'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)
  server.add_insecure_port('[::]:{}'.format(port))
  server.start()

  print('Listening on port {}'.format(port))
  try:
    while True:
      time.sleep(3600)
  except KeyboardInterrupt:
    print('Shutting down with {} grace period'.format(_SHUTDOWN_GRACE_DURATION))
    server.stop(_SHUTDOWN_GRACE_DURATION)


def is_cloud_run() -> bool:
  """Check if we are running in Cloud Run."""
  # https://cloud.google.com/run/docs/container-contract#env-vars
  return os.getenv('K_SERVICE') is not None


def main():
  """Entrypoint."""
  if is_cloud_run():
    setup_gcp_logging('api-backend')

  logging.getLogger().setLevel(logging.INFO)

  parser = argparse.ArgumentParser(
      formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument(
      '--port',
      type=int,
      default=None,
      help='The port to listen on.'
      'If arg is not set, will listen on the $PORT env var.'
      'If env var is empty, defaults to 8000.')
  parser.add_argument(
      '--local',
      action='store_true',
      default=False,
      help='If set reflection is enabled to allow debugging with grpcurl.')

  args = parser.parse_args()
  port = args.port
  if not port:
    port = os.environ.get('PORT')
  if not port:
    port = 8000

  serve(port, args.local)


if __name__ == '__main__':
  main()
