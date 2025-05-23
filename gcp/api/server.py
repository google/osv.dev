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
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
import hashlib
import functools
import logging
import os
import threading
import time
import concurrent.futures
from typing import Callable

from collections import defaultdict

from google.cloud import ndb
from google.api_core.exceptions import InvalidArgument
import google.cloud.ndb.exceptions as ndb_exceptions

import grpc
from grpc_health.v1 import health_pb2
from grpc_health.v1 import health_pb2_grpc
from grpc_reflection.v1alpha import reflection
from packaging.utils import canonicalize_version

import osv
from osv import ecosystems
from osv import semver_index
from osv import purl_helpers
from osv import vulnerability_pb2
from osv.logs import setup_gcp_logging
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

from cursor import QueryCursor

import googlecloudprofiler

_SHUTDOWN_GRACE_DURATION = 5

_MAX_SINGLE_QUERY_TIME = timedelta(seconds=20)
_MAX_BATCH_QUERY_TIME = timedelta(seconds=35)
_MAX_BATCH_QUERY = 1000
# Maximum number of responses to return before applying post exceeded limit
_MAX_VULN_RESP_THRESH = 3000
# Max responses after MAX_VULN_RESP_THRESH has been exceeded
_MAX_VULN_LISTED_POST_EXCEEDED = 5
# Max responses before MAX_VULN_RESP_THRESH has been exceeded
_MAX_VULN_LISTED_PRE_EXCEEDED = 1000

_MAX_VULN_LISTED_PRE_EXCEEDED_UBUNTU_EXCEPTION = 50

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

# This needs to be kept in sync with
# https://github.com/google/osv.dev/blob/master/docker/indexer/stages/processing/processing.go#L77
_VENDORED_LIB_NAMES = frozenset((
    '3rdparty',
    'dep',
    'deps',
    'thirdparty',
    'third-party',
    'third_party',
    'libs',
    'external',
    'externals',
    'vendor',
    'vendored',
))

# Prefix for the
_TAG_PREFIX = "refs/tags/"

_TEST_INSTANCE = 'oss-vdb-test'

# ----
# Type Aliases:

ToResponseCallable = Callable[[osv.Bug], vulnerability_pb2.Vulnerability]

# ----

_ndb_client = ndb.Client()


def ndb_context(func):
  """Wrapper to create an NDB context."""

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    with _ndb_client.context():
      return func(*args, **kwargs)

  return wrapper


class LogTraceFilter:
  """Class for adding the trace information from the grpc requests into logs."""

  def __init__(self):
    self.thread_local = threading.local()

  def log_trace(self, func):
    """Wrapper for grpc method to capture trace from header metadata"""

    @functools.wraps(func)
    def wrapper(s, r, context: grpc.ServicerContext):
      self.thread_local.trace = dict(
          context.invocation_metadata()).get('x-cloud-trace-context')
      return func(s, r, context)

    return wrapper

  def filter(self, record: logging.LogRecord) -> bool:
    """logging.Filter method to add trace into log data."""
    trace = getattr(self.thread_local, 'trace', None)
    if not trace:
      return True

    # Trace context header example:
    # "X-Cloud-Trace-Context: TRACE_ID/SPAN_ID;o=TRACE_TRUE"
    parts = trace.split('/')
    trace_id = parts[0]
    project = get_gcp_project()
    record.trace = f'projects/{project}/traces/{trace_id}'
    if len(parts) > 1:
      record.span_id = parts[1].split(';')[0]

    return True


trace_filter = LogTraceFilter()


class OSVServicer(osv_service_v1_pb2_grpc.OSVServicer,
                  health_pb2_grpc.HealthServicer):
  """V1 OSV servicer."""

  @ndb_context
  @trace_filter.log_trace
  def GetVulnById(self, request, context: grpc.ServicerContext):
    """Return a `Vulnerability` object for a given OSV ID."""
    bug = osv.Bug.get_by_id(request.id)
    if not bug or bug.status == osv.BugStatus.UNPROCESSED:
      context.abort(grpc.StatusCode.NOT_FOUND, 'Bug not found.')
      return None

    if not bug.public:
      context.abort(grpc.StatusCode.PERMISSION_DENIED, 'Permission denied.')
      return None

    return bug_to_response(bug, include_alias=True)

  @ndb_context
  @trace_filter.log_trace
  def QueryAffected(self, request, context: grpc.ServicerContext):
    """Query vulnerabilities for a particular project at a given commit or

    version.
    """
    # Log some information about the query with structured logging
    qtype, ecosystem, versioned = query_info(request.query)
    if ecosystem is not None:
      logging.info(
          'QueryAffected for %s "%s"',
          qtype,
          ecosystem,
          extra={
              'json_fields': {
                  'details': {
                      'ecosystem': ecosystem,
                      'versioned': versioned == 'versioned'
                  }
              }
          })
    else:
      logging.info('QueryAffected for %s', qtype)

    # Log queries for test instance.
    # This is for debugging purposes. Production queries will not be recorded.
    if get_gcp_project() == _TEST_INSTANCE:
      logging.info('Query: %s', request.query)
    try:
      page_token = QueryCursor.from_page_token(request.query.page_token)
    except ValueError as e:
      logging.warning(e)
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid page token.')
      # This is just for the type checker which doesn't know
      # abort will kill the code flow
      raise

    query_context = QueryContext(
        service_context=context,
        request_cutoff_time=datetime.now() + _MAX_SINGLE_QUERY_TIME,
        input_cursor=page_token,
        output_cursor=QueryCursor(),
        total_responses=ResponsesCount(0))

    try:
      results, next_page_token = do_query(
          request.query, query_context).result()  # type: ignore
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
  @trace_filter.log_trace
  def QueryAffectedBatch(self, request, context: grpc.ServicerContext):
    """Query vulnerabilities (batch)."""
    batch_results = []
    futures = []

    # Log some information about the query with structured logging e.g.
    # "message": "QueryAffectedBatch with 15 queries",
    # "details": {
    #   "commit": 1,
    #   "ecosystem": {
    #     "PyPI": {
    #       "versioned": 4,
    #       "versionless": 5
    #      },
    #     "": {  // no ecosystem specified
    #       "versioned": 1,
    #     }
    #   },
    #   "purl": {
    #     "golang": {  // purl type, not OSV ecosystem
    #       "versionless": 1
    #     }
    #   }
    #   "invalid": 2
    # }
    # Fields are not included if the value is empty/0
    query_details = {
        'commit': 0,
        'ecosystem': defaultdict(lambda: defaultdict(int)),
        'purl': defaultdict(lambda: defaultdict(int)),
        'invalid': 0,
    }
    for query in request.query.queries:
      qtype, ecosystem, versioned = query_info(query)
      if ecosystem is not None:
        query_details[qtype][ecosystem][versioned] += 1
      else:
        query_details[qtype] += 1

    # Filter out empty fields
    query_details = {k: v for k, v in query_details.items() if v}

    logging.info(
        'QueryAffectedBatch with %d queries',
        len(request.query.queries),
        extra={'json_fields': {
            'details': query_details
        }})
    # Log queries for test instance.
    # This is for debugging purposes. Production queries will not be recorded.
    if get_gcp_project() == _TEST_INSTANCE:
      logging.info('Batch query: %s', request.query)

    if len(request.query.queries) > _MAX_BATCH_QUERY:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Too many queries.')
      return None

    total_responses = ResponsesCount(0)
    req_cutoff_time = datetime.now() + _MAX_BATCH_QUERY_TIME
    for i, query in enumerate(request.query.queries):
      try:
        page_token = QueryCursor.from_page_token(query.page_token)
      except ValueError as e:
        logging.warning(e)
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                      f'Invalid page token at index: {i}.')
        # This is just for the type checker which doesn't know
        # abort will kill the code flow
        raise

      query_context = QueryContext(
          service_context=context,
          request_cutoff_time=req_cutoff_time,
          input_cursor=page_token,
          output_cursor=QueryCursor(),
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
  @trace_filter.log_trace
  def DetermineVersion(self, request, context: grpc.ServicerContext):
    """Determine the version of the provided hashes."""
    res = determine_version(request.query, context).result()
    return res

  @ndb_context
  @trace_filter.log_trace
  def ImportFindings(self, request, context: grpc.ServicerContext):
    """Return a list of `ImportFinding` for a given source."""
    source = request.source
    # TODO(gongh@): add source check,
    # check if the source name exists in the source repository.
    if not source:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    'Missing Source:  Please specify the source')
    if get_gcp_project() == _TEST_INSTANCE:
      logging.info('Checking import finding for %s\n', source)

    query = osv.ImportFinding.query(osv.ImportFinding.source == source)
    import_findings: list[osv.ImportFinding] = query.fetch()
    invalid_records = []
    for finding in import_findings:
      invalid_records.append(finding.to_proto())

    return osv_service_v1_pb2.ImportFindingList(invalid_records=invalid_records)

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


def query_info(query) -> tuple[str, str | None, str | None]:
  """Returns information about a query, for logging purposes.
  First return value is one of 'commit', 'purl', 'ecosystem', 'invalid'.
  If 'ecosystem' or 'purl', second two return values are the ecosystem name,
  then 'versioned' or 'versionless' depending if the 'version' field is set.
  Otherwise, last two return values are None.
  """
  if query.WhichOneof('param') == 'commit':
    return 'commit', None, None
  if not query.HasField('package'):
    return 'invalid', None, None
  if not query.package.purl and not query.package.name:
    return 'invalid', None, None
  qtype = 'ecosystem'
  ecosystem = query.package.ecosystem
  version = query.version
  if query.package.purl:
    try:
      purl = purl_helpers.parse_purl(query.package.purl)  # can raise ValueError
      if purl is None:
        raise ValueError('purl ecosystem is unknown')
      if query.package.ecosystem or query.package.name:
        raise ValueError('purl and name/ecosystem cannot both be specified')
      if purl.version and query.version:
        raise ValueError('purl version and version cannot both be specified')
      qtype = 'purl'
      ecosystem = purl.ecosystem
      version = purl.version or version
    except ValueError:
      return 'invalid', None, None

  return qtype, ecosystem, 'versioned' if version else 'versionless'


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
  """
  Information about the query the server is currently
  responding to.

  Attributes:
    service_context: Context of the underlying grpc call.
    input_cursor: Cursor from the user API query input.
    output_cursor: Cursor to potentially return to the user.
    request_cutoff_time: Time past which all further datastore 
      queries stop and a page cut is made.
    total_responses: **Reference** to the total count of responses
      across all queries in the batch.
    query_counter: Number of queries which has already been executed
      (does not count batch queries).
  """
  service_context: grpc.ServicerContext
  input_cursor: QueryCursor
  output_cursor: QueryCursor
  request_cutoff_time: datetime
  # Use a dataclass to copy by reference
  total_responses: ResponsesCount
  query_counter: int = 0
  single_page_limit_override: int | None = None

  def should_break_page(self, response_count: int):
    """
    Returns whether the API should finish its current page here 
    and return a cursor.

    Currently uses two criteria:
      - total response size greater than page limit
      - request exceeding the cutoff time
    """
    page_limit = self.total_responses.page_limit()
    if (self.single_page_limit_override and
        not self.total_responses.exceeded()):
      page_limit = self.single_page_limit_override

    return (response_count >= page_limit or
            datetime.now() > self.request_cutoff_time)

  def should_skip_query(self):
    """
    Returns whether a query should be executed or skipped depending
    on the cursor position.

    A query should be skipped when:
      - Input cursor is for a future query
      - Output cursor is not ended(), which means we already hit page limit
        in a previous query.
    """
    return (self.query_counter < self.input_cursor.query_number or
            not self.output_cursor.ended)

  def cursor_at_current(self) -> ndb.Cursor | None:
    """
    Return the cursor if the stored cursor is for the current query.
    """
    if self.input_cursor.query_number == self.query_counter:
      return self.input_cursor.ndb_cursor

    return None

  def save_cursor_at_page_break(self, it: ndb.QueryIterator):
    """
    Saves the cursor at the current page break position
    """
    self.output_cursor.update_from_iterator(it)
    self.output_cursor.query_number = self.query_counter


def should_skip_bucket(path: str) -> bool:
  """Returns whether or not the given file path should be skipped for the
  determineversions bucket computation."""
  if not path:
    return False

  # Check for a nested vendored directory, as this could mess with results. The
  # API expects the file path passed to be relative to the potential library
  # path, so any vendored library names found here would imply it's a nested
  # vendored library.
  components = path.split('/')
  return any(c in _VENDORED_LIB_NAMES for c in components)


def process_buckets(
    file_results: list[osv.FileResult]) -> list[osv.RepoIndexBucket]:
  """
  Create buckets in the same process as 
  indexer to generate the same bucket hashes
  """
  buckets: list[list[bytes]] = [[] for _ in range(_BUCKET_SIZE)]

  for fr in file_results:
    if should_skip_bucket(fr.path):
      continue

    buckets[int.from_bytes(fr.hash[:2], byteorder='big') % _BUCKET_SIZE].append(
        fr.hash)

  results: list[osv.RepoIndexBucket] = []
  for bucket in buckets:
    bucket.sort()

    hasher = hashlib.md5()
    for v in bucket:
      hasher.update(v)

    results.append(
        osv.RepoIndexBucket(
            node_hash=hasher.digest(),
            files_contained=len(bucket),
        ))

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
  idx_futures = ndb.get_multi_async([b[0] for b in bucket_match_items
                                    ])  # type: ignore
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
  logging.info("DetermineVersion for %d hashes", len(version_query.file_hashes))

  req_list = []
  for x in version_query.file_hashes:
    if x.hash is not None and len(x.hash) <= 100:
      # We are expecting MD5 hashes which should not be super long.
      req_list.append(osv.FileResult(hash=x.hash))

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
        parent_key = index_bucket.key.parent()  # type: ignore
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
def do_query(query: osv_service_v1_pb2.Query,
             context: QueryContext,
             include_details=True) -> tuple[list, str | None]:
  """Do a query."""
  package_name = ''
  ecosystem = ''
  purl_str = ''
  version = ''

  if query.HasField('package'):
    package_name = query.package.name
    ecosystem = query.package.ecosystem
    purl_str = query.package.purl

  if query.HasField('version'):
    version = query.version

  # convert purl to package names
  if purl_str:
    try:
      purl = purl_helpers.parse_purl(purl_str)
    except ValueError as e:
      context.service_context.abort(
          grpc.StatusCode.INVALID_ARGUMENT,
          f'{e}',
      )

    if package_name:  # Purls already include the package name
      context.service_context.abort(
          grpc.StatusCode.INVALID_ARGUMENT,
          'name specified in a PURL query',
      )

    if ecosystem:
      # Purls already include the ecosystem inside
      context.service_context.abort(
          grpc.StatusCode.INVALID_ARGUMENT,
          'ecosystem specified in a PURL query',
      )

    if purl is None:
      # TODO(gongh@): Previously, we didn't perform any PURL validation.
      # All unsupported PURL queries would simply return a 200
      # status code with an empty response.
      # To avoid breaking existing behavior,
      # we return an empty response here with no error.
      # This needs to be revisited with a more considerate design.
      return [], None

    if purl.version and version:
      # version included both in purl and query
      context.service_context.abort(
          grpc.StatusCode.INVALID_ARGUMENT,
          'version specified in params and PURL query',
      )

    ecosystem = purl.ecosystem
    package_name = purl.package
    if purl.version:
      version = purl.version

  if ecosystem and not ecosystems.get(ecosystem):
    context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                  'Invalid ecosystem.')

  # Normalize package names as necessary.
  if package_name:
    package_name = ecosystems.maybe_normalize_package_names(
        package_name, ecosystem)

  # Hack to work around ubuntu having extremely large individual entries
  if ecosystem.startswith('Ubuntu'):
    # Specifically the linux entries
    if 'linux' in package_name:
      context.single_page_limit_override = \
        _MAX_VULN_LISTED_PRE_EXCEEDED_UBUNTU_EXCEPTION

  def to_response(b: osv.Bug):
    # Skip retrieving aliases from to_vulnerability().
    # Retrieve it asynchronously later.
    return bug_to_response(b, include_details)

  bugs: list[vulnerability_pb2.Vulnerability]
  if query.WhichOneof('param') == 'commit':
    try:
      commit_bytes = codecs.decode(query.commit, 'hex')
    except ValueError:
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                    'Invalid hash.')
      return None

    bugs = yield query_by_commit(context, commit_bytes, to_response=to_response)
  # Version query needs to include a package.
  elif package_name and version:
    bugs = yield query_by_version(
        context, package_name, ecosystem, version, to_response=to_response)
  elif package_name and ecosystem:
    # Package specified without version.
    bugs = yield query_by_package(
        context, package_name, ecosystem, to_response=to_response)
  else:
    context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                  'Invalid query.')
    # This will never be reached, and is just here for the type checker,
    # to know that control flow breaks here.
    raise ValueError

  # Asynchronously retrieve computed aliases and related ids here
  # to prevent significant query time increase for packages with
  # numerous vulnerabilities.
  if include_details:
    aliases = []
    related = []
    for bug in bugs:
      aliases.append(osv.get_aliases_async(bug.id))
      related.append(osv.get_related_async(bug.id))

    for i, alias in enumerate(aliases):
      alias_group: osv.AliasGroup = yield alias
      if not alias_group:
        continue
      alias_ids = sorted(list(set(alias_group.bug_ids) - {bugs[i].id}))
      bugs[i].aliases[:] = alias_ids
      modified_time = bugs[i].modified.ToDatetime()
      modified_time = max(alias_group.last_modified, modified_time)
      bugs[i].modified.FromDatetime(modified_time)

    for i, related_ids in enumerate(related):
      related_bug_ids: list[str] = yield related_ids
      bugs[i].related[:] = sorted(
          list(set(related_bug_ids + list(bugs[i].related))))

  if context.query_counter < context.input_cursor.query_number:
    logging.error(
        'Cursor is invalid - received "%d" while total query count is "%d".',
        context.input_cursor.query_number, context.query_counter)
    # If the input cursor is for a query number that's greater than
    # the number of queries performed, the cursor must be invalid
    # (and there will be no results, as everything is skipped)
    raise ValueError('Cursor is invalid/does not belong to this query')

  next_page_token_str = context.output_cursor.url_safe_encode()
  if next_page_token_str:
    logging.warning('Page size limit hit, response size: %s', len(bugs))

  return bugs, next_page_token_str


def bug_to_response(bug: osv.Bug,
                    include_details=True,
                    include_alias=False) -> vulnerability_pb2.Vulnerability:
  """Convert a Bug entity to a response object."""
  if include_details:
    return bug.to_vulnerability(
        include_source=True, include_alias=include_alias)

  return bug.to_vulnerability_minimal()


@ndb.tasklet
def _get_bugs(
    bug_ids: list[str],
    to_response: ToResponseCallable = bug_to_response
) -> list[vulnerability_pb2.Vulnerability]:
  """Get bugs from bug ids."""
  bugs = ndb.get_multi_async([ndb.Key(osv.Bug, bug_id) for bug_id in bug_ids
                             ])  # type: ignore

  responses = []
  for future_bug in bugs:
    bug: osv.Bug = yield future_bug
    if bug and bug.status == osv.BugStatus.PROCESSED and bug.public:
      responses.append(to_response(bug))

  return responses


@ndb.tasklet
def query_by_commit(
    context: QueryContext,
    commit: bytes,
    to_response: ToResponseCallable = bug_to_response
) -> list[vulnerability_pb2.Vulnerability]:
  """
  Perform a query by commit.

  This is a ndb.tasklet, so will return a future that will need to be yielded.

  Args:
    context: QueryContext for the current query.
    commit: The commit hash to query.
    to_response: Optional function to convert osv.Bug to a 
      vulnerability response.

  Returns:
    list of responses (return values from to_response)
  """
  query = osv.AffectedCommits.query(osv.AffectedCommits.commits == commit)

  context.query_counter += 1
  if context.should_skip_query():
    return []

  bug_ids = []
  it: ndb.QueryIterator = query.iter(
      keys_only=True, start_cursor=context.cursor_at_current())

  while (yield it.has_next_async()):
    if context.should_break_page(len(bug_ids)):
      context.save_cursor_at_page_break(it)
      break

    # Affect commits key follows this format:
    # <BugID>-<PageNumber>
    affected_commits: ndb.Key = it.next()
    bug_id: str = affected_commits.id().rsplit("-", 1)[0]

    bug_ids.append(bug_id)
    context.total_responses.add(1)

  bugs = yield _get_bugs(bug_ids, to_response=to_response)
  return bugs


def _is_semver_affected(affected_packages: list[osv.AffectedPackage],
                        package_name: str | None, ecosystem: str | None,
                        version_str: str):
  """Returns whether or not the given version is within an affected SEMVER

  range.
  """
  version = semver_index.parse(version_str)

  affected = False
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem and ecosystem != affected_package.package.ecosystem:
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
                         version,
                         normalize=False):
  """
  Returns whether or not the given version is within an affected ECOSYSTEM
  range.
  """
  for affected_package in affected_packages:
    if ecosystem:
      # If package ecosystem has a :, also try ignoring parts after it.
      if not is_matching_package_ecosystem(affected_package.package.ecosystem,
                                           ecosystem):
        continue

    if package_name:
      if ecosystem == 'GIT':
        # Special case for git ecosystems to match repo urls
        repo_url = ''
        for rg in affected_package.ranges:
          if rg.repo_url != '':
            repo_url = rg.repo_url
            break

        if package_name != repo_url:
          continue
      else:
        if package_name != affected_package.ranges:
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
def _query_by_semver(context: QueryContext, query: ndb.Query,
                     package_name: str | None, ecosystem: str | None,
                     version: str) -> list[osv.Bug]:
  """
  Perform a query by semver version.

  This is a ndb.tasklet, so will return a future that will need to be yielded.

  Args:
    context: QueryContext for the current query.
    query: A partially completed ndb.Query object which only needs 
      semver filters to be added before query is performed.
    package_name: Optional name of the package to query.
    ecosystem: Optional ecosystem of the package to query.
    version: The semver version to query for.

  Returns:
    list of osv.Bug entries wrapped in a Future.
  """
  if not semver_index.is_valid(version):
    return []

  results = []
  query = query.filter(osv.Bug.semver_fixed_indexes
                       > semver_index.normalize(version))  # type: ignore

  context.query_counter += 1
  if context.should_skip_query():
    return []

  it: ndb.QueryIterator = query.iter(start_cursor=context.cursor_at_current())

  while (yield it.has_next_async()):
    if context.should_break_page(len(results)):
      context.save_cursor_at_page_break(it)
      break

    bug: osv.Bug = it.next()  # type: ignore
    if _is_semver_affected(bug.affected_packages, package_name, ecosystem,
                           version):
      results.append(bug)
      context.total_responses.add(1)

  return results


@ndb.tasklet
def _query_by_generic_version(
    context: QueryContext,
    base_query: ndb.Query,
    package_name: str | None,
    ecosystem: str | None,
    version: str,
) -> list[osv.Bug]:
  """
  Query by generic version. 
  
  This is a ndb.tasklet, so will return a future that will need to be yielded.

  Args:
    context: QueryContext for the current query.
    base_query: A partially completed ndb.Query object which only needs 
      version filters to be added before query is performed.
    package_name: Optional name of the package to query.
    ecosystem: Optional ecosystem of the package to query.
    version: The non-semver version to query for.
  
  Returns:
    list of osv.Bug entries wrapped in a Future.
  """
  # Try without normalizing.
  results = yield query_by_generic_helper(context, base_query, package_name,
                                          ecosystem, version, False)

  # If there are results, then we should return with this query,
  # as no normalization seem to be the correct format.
  if results:
    return results

  results = yield query_by_generic_helper(context, base_query,
                                          package_name, ecosystem,
                                          osv.normalize_tag(version), True)

  if results:
    return results

  # Try again after canonicalizing + normalizing version.
  results = yield query_by_generic_helper(context, base_query, package_name,
                                          ecosystem,
                                          canonicalize_version(version), True)

  return results


@ndb.tasklet
def query_by_generic_helper(context: QueryContext, base_query: ndb.Query,
                            package_name: str | None, ecosystem: str | None,
                            version: str, is_normalized: bool) -> list[osv.Bug]:
  """
  Helper function for query_by_generic. 
  This function can be called multiple times.
  """
  query: ndb.Query = base_query.filter(osv.Bug.affected_fuzzy == version)
  results: list[osv.Bug] = []
  context.query_counter += 1
  if context.should_skip_query():
    return []

  it: ndb.QueryIterator = query.iter(start_cursor=context.cursor_at_current())

  while (yield it.has_next_async()):
    if context.should_break_page(len(results)):
      context.save_cursor_at_page_break(it)
      break
    bug: osv.Bug = it.next()  # type: ignore
    if _is_version_affected(
        bug.affected_packages,
        package_name,
        ecosystem,
        version,
        normalize=is_normalized):
      results.append(bug)
      context.total_responses.add(1)
  return results


@ndb.tasklet
def query_by_version(
    context: QueryContext,
    package_name: str | None,
    ecosystem: str | None,
    version: str,
    to_response: ToResponseCallable = bug_to_response
) -> list[vulnerability_pb2.Vulnerability]:
  """
  Query by (fuzzy) version.

  This is a ndb.tasklet, so will return a future that will need to be yielded.

  Args:
    context: QueryContext for the current query.
    package_name: Optional name of the package to query.
    ecosystem: Optional ecosystem of the package to query.
    version: The version str to query by.
    to_response: Optional function to convert osv.Bug to a 
      vulnerability response.

  Returns:
    list of responses (return values from to_response)
  """

  if package_name:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.project == package_name,
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  else:
    return []

  ecosystem_info = None
  if ecosystem:
    query = query.filter(osv.Bug.ecosystem == ecosystem)
    ecosystem_info = ecosystems.get(ecosystem)

  is_semver = ecosystem_info and ecosystem_info.is_semver
  supports_comparing = ecosystem_info and ecosystem_info.supports_comparing

  bugs = []
  if ecosystem:
    if is_semver:
      # Ecosystem supports semver only.
      bugs = yield _query_by_semver(context, query, package_name, ecosystem,
                                    version)

      # If the previous query has fully finished (or skipped),
      # try generic version
      new_bugs = yield _query_by_generic_version(context, query, package_name,
                                                 ecosystem, version)
      for bug in new_bugs:
        if bug not in bugs:
          bugs.append(bug)
    elif supports_comparing:
      # Query for non-enumerated ecosystems.
      bugs = yield _query_by_comparing_versions(context, query, package_name,
                                                ecosystem, version)
    else:
      bugs = yield _query_by_generic_version(context, query, package_name,
                                             ecosystem, version)

  else:
    logging.warning("Package query without ecosystem specified")
    # Unspecified ecosystem. Try semver first.
    new_bugs = yield _query_by_semver(context, query, package_name, ecosystem,
                                      version)
    bugs.extend(new_bugs)

    new_bugs = yield _query_by_generic_version(context, query, package_name,
                                               ecosystem, version)
    for bug in new_bugs:
      if bug not in bugs:
        bugs.append(bug)

    # Our documentation states that this is an invalid query
    # context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT,
    #                               'Ecosystem not specified')

  return [to_response(bug) for bug in bugs]


@ndb.tasklet
def _query_by_comparing_versions(context: QueryContext, query: ndb.Query,
                                 package_name: str, ecosystem: str,
                                 version: str) -> list[osv.Bug]:
  """
  Query by comparing versions.

  Args:
    context: QueryContext for the current query.
    query: A partially completed ndb.Query object which only needs 
      version filters to be added before query is performed.
    package_name: Required name of the package to query.
    ecosystem: Required ecosystem of the package to query.
    version: The version str to query by.

  Returns:
    list of osv.Bugs
  """
  bugs: list[osv.Bug] = []

  context.query_counter += 1
  if context.should_skip_query():
    return []

  it: ndb.QueryIterator = query.iter(start_cursor=context.cursor_at_current())

  while (yield it.has_next_async()):
    try:
      if context.should_break_page(len(bugs)):
        context.save_cursor_at_page_break(it)
        break

      # next() will never return None as we check for has next above.
      bug: osv.Bug = it.next()  # type: ignore
      for affected_package in bug.affected_packages:  # type: ignore
        affected_package: osv.AffectedPackage
        package: osv.Package = affected_package.package  # type: ignore

        # If the queried ecosystem has no release specified (e.g., "Debian"),
        # compare against packages in all releases (e.g., "Debian:X").
        # Otherwise, only compare within
        # the specified release (e.g., "Debian:11").
        # Skips if the affected package ecosystem does not match
        # the queried ecosystem.
        if not is_matching_package_ecosystem(package.ecosystem, ecosystem):
          continue

        # Skips if the affected package name does not match
        # the queried package name.
        if package_name != package.name:
          continue

        if _is_affected(ecosystem, version, affected_package):
          bugs.append(bug)
          context.total_responses.add(1)
          break
    except Exception:
      logging.exception('failed to compare versions')

  return bugs


@ndb.tasklet
def query_by_package(
    context: QueryContext, package_name: str | None, ecosystem: str | None,
    to_response: ToResponseCallable) -> list[vulnerability_pb2.Vulnerability]:
  """
  Query by package.
  
  This is a ndb.tasklet, so will return a future that will need to be yielded.

  Args:
    context: QueryContext for the current query.
    package_name: Optional name of the package to query.
    ecosystem: Optional ecosystem of the package to query.
    to_response: Function to convert osv.Bug to a 
      vulnerability response.

  Returns:
    list of responses (return values from to_response)
  """
  bugs = []
  if package_name and ecosystem:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.project == package_name,
        osv.Bug.ecosystem == ecosystem,
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  else:
    return []

  context.query_counter += 1
  if context.should_skip_query():
    return []

  it: ndb.QueryIterator = query.iter(start_cursor=context.cursor_at_current())

  while (yield it.has_next_async()):
    if context.should_break_page(len(bugs)):
      context.save_cursor_at_page_break(it)
      break

    bug: osv.Bug = it.next()  # type: ignore

    bugs.append(bug)
    context.total_responses.add(1)

  return [to_response(bug) for bug in bugs]


def serve(port: int, local: bool):
  """Configures and runs the OSV API server."""
  server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=5))
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


def get_gcp_project():
  """Get the GCP project name."""
  # We don't set the GOOGLE_CLOUD_PROJECT env var explicitly, and I can't find
  # any confirmation on whether Cloud Run will set automatically.
  # Grab the project name from the (undocumented?) field on ndb.Client().
  # Most correct way to do this would be to use the instance metadata server
  # https://cloud.google.com/run/docs/container-contract#metadata-server
  return getattr(_ndb_client, 'project', 'oss-vdb')  # fall back to oss-vdb


def _is_affected(ecosystem: str, version: str,
                 affected_package: osv.AffectedPackage) -> bool:
  """Checks if a version is affected."""
  affected = False
  ecosystem_info = ecosystems.get(ecosystem)
  queried_version = ecosystem_info.sort_key(version)

  # OSV allows users to add affected versions
  # that are not covered by affected ranges.
  if version in affected_package.versions:
    return True

  for r in affected_package.ranges:
    r: osv.AffectedRange2

    for event in osv.sorted_events(ecosystem, r.type, r.events):
      event: osv.AffectedEvent
      if (event.type == 'introduced' and
          (event.value == '0' or
           queried_version >= ecosystem_info.sort_key(event.value))):
        affected = True
      elif (event.type == 'fixed' and
            queried_version >= ecosystem_info.sort_key(event.value)):
        affected = False
      elif (event.type == 'last_affected' and
            queried_version > ecosystem_info.sort_key(event.value)):
        affected = False

    if affected:
      return True

  return False


def is_matching_package_ecosystem(package_ecosystem: str,
                                  ecosystem: str) -> bool:
  """Checks if the queried ecosystem matches the affected package's ecosystem,
  considering potential variations in the package's ecosystem.
  """

  # Special case for GIT queries, for which osv entries will have an empty ecosystem for.
  if ecosystem == 'GIT' and package_ecosystem == '':
    return True

  return any(eco == ecosystem for eco in (
      package_ecosystem,
      ecosystems.normalize(package_ecosystem),
      ecosystems.remove_variants(package_ecosystem),
  ))


def main():
  """Entrypoint."""
  if is_cloud_run():
    setup_gcp_logging('api-backend')
    logging.getLogger().addFilter(trace_filter)

    # Profiler initialization. It starts a daemon thread which continuously
    # collects and uploads profiles. Best done as early as possible.
    try:
      googlecloudprofiler.start(service="osv-api-profiler")
    except (ValueError, NotImplementedError) as e:
      logging.error(e)

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
    port = int(os.environ.get('PORT', '8000'))

  serve(port, args.local)


if __name__ == '__main__':
  main()
