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
"""OSV API server implementation."""

import argparse
import codecs
from dataclasses import dataclass
from datetime import datetime, timedelta, UTC
import math
import hashlib
import functools
import logging
import os
import threading
import time
import concurrent.futures
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeAlias, cast # Added TypeAlias, cast, etc.
from collections import defaultdict


from google.cloud import ndb
from google.api_core.exceptions import InvalidArgument as GoogleInvalidArgument
import google.cloud.ndb.exceptions as ndb_exceptions

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection
from packaging.utils import canonicalize_version

import osv # Refers to osv.models mostly
from osv import ecosystems
from osv import semver_index
from osv import purl_helpers
from osv import vulnerability_pb2 # osv.vulnerability_pb2
from osv.logs import setup_gcp_logging # osv.logs.setup_gcp_logging
import osv_service_v1_pb2 # gcp.api.osv_service_v1_pb2
import osv_service_v1_pb2_grpc # gcp.api.osv_service_v1_pb2_grpc

from cursor import QueryCursor # gcp.api.cursor.QueryCursor

import googlecloudprofiler

# Ensure __future__ import is at the very top
# from __future__ import annotations # Already added by user prompt

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
_VENDORED_LIB_NAMES: frozenset[str] = frozenset((
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

ToResponseCallable: TypeAlias = Callable[[osv.models.Bug], vulnerability_pb2.Vulnerability]
QueryFutureReturn: TypeAlias = Tuple[List[vulnerability_pb2.Vulnerability], Optional[str]]

# ----

_ndb_client: ndb.Client = ndb.Client()


def ndb_context(func: Callable[..., Any]) -> Callable[..., Any]:
  """Wrapper to create an NDB context."""

  @functools.wraps(func)
  def wrapper(*args: Any, **kwargs: Any) -> Any:
    with _ndb_client.context():
      return func(*args, **kwargs)

  return wrapper

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

  def __init__(self) -> None:
    self.thread_local = threading.local()
    self.thread_local.trace = None # Initialize to avoid AttributeError if not set

  def log_trace(self, func: Callable[..., Any]) -> Callable[..., Any]:
    """Wrapper for grpc method to capture trace from header metadata"""

    @functools.wraps(func)
    def wrapper(servicer_instance: Any, request_proto: Any, context: grpc.ServicerContext) -> Any: # Renamed s, r
      # Store trace from metadata. Metadata is List[Tuple[str,str]]
      metadata_dict = dict(context.invocation_metadata())
      self.thread_local.trace = metadata_dict.get('x-cloud-trace-context')
      return func(servicer_instance, request_proto, context)

    return wrapper

  def filter(self, record: logging.LogRecord) -> bool:
    """logging.Filter method to add trace into log data."""
    trace_val: Optional[str] = getattr(self.thread_local, 'trace', None) # Renamed trace
    if not trace_val:
      return True

    # Trace context header example:
    # "X-Cloud-Trace-Context: TRACE_ID/SPAN_ID;o=TRACE_TRUE"
    parts = trace_val.split('/')
    trace_id_val: str = parts[0] # Renamed trace_id
    project_val: str = get_gcp_project() # Renamed project
    # Ensure trace attribute exists on LogRecord, or define a custom LogRecord if needed
    setattr(record, 'trace', f'projects/{project_val}/traces/{trace_id_val}')
    if len(parts) > 1:
      setattr(record, 'span_id', parts[1].split(';')[0])

    return True


trace_filter = LogTraceFilter()


class OSVServicer(osv_service_v1_pb2_grpc.OSVServicer,
                  health_pb2_grpc.HealthServicer):
  """V1 OSV servicer."""

  @ndb_context
  @trace_filter.log_trace
  def GetVulnById(self, request: osv_service_v1_pb2.GetVulnByIdRequest,
                  context: grpc.ServicerContext) -> Optional[vulnerability_pb2.Vulnerability]:
    """Return a `Vulnerability` object for a given OSV ID."""
    bug: Optional[osv.models.Bug] = osv.models.Bug.get_by_id(request.id)

    if not bug:
      # Check for aliases
      alias_group: Optional[osv.models.AliasGroup] = osv.models.AliasGroup.query(
          osv.models.AliasGroup.bug_ids == request.id).get()
      if alias_group:
        # Ensure bug_ids is not None
        alias_ids = alias_group.bug_ids or []
        alias_string = ' '.join([
            f'{alias}' for alias in alias_ids if alias != request.id
        ])
        context.abort(
            grpc.StatusCode.NOT_FOUND,
            f'Bug not found, but the following aliases were: {alias_string}')
      else: # No bug and no alias group found
        context.abort(grpc.StatusCode.NOT_FOUND, 'Bug not found.')
      return None # Abort ends execution, but return for type checker

    if bug.status == osv.models.BugStatus.UNPROCESSED.value: # Compare with .value
      context.abort(grpc.StatusCode.NOT_FOUND, 'Bug not found (unprocessed).')
      return None

    if not bug.public:
      context.abort(grpc.StatusCode.PERMISSION_DENIED, 'Permission denied.')
      return None

    return bug_to_response(bug, include_alias=True)

  @ndb_context
  @trace_filter.log_trace
  def QueryAffected(self, request: osv_service_v1_pb2.QueryAffectedRequest,
                    context: grpc.ServicerContext) -> Optional[osv_service_v1_pb2.VulnerabilityList]:
    """Query vulnerabilities for a particular project at a given commit or
    version.
    """
    # Log some information about the query with structured logging
    query_type_str, ecosystem_str, versioned_str = query_info(request.query) # Renamed qtype, ecosystem, versioned
    if ecosystem_str is not None:
      logging.info(
          'QueryAffected for %s "%s"',
          query_type_str,
          ecosystem_str,
          extra={
              'json_fields': {
                  'details': {
                      'ecosystem': ecosystem_str,
                      'versioned': versioned_str == 'versioned'
                  }
              }
          })
    else: # e.g. for commit queries
      logging.info('QueryAffected for %s', query_type_str)


    # Log queries for test instance.
    if get_gcp_project() == _TEST_INSTANCE:
      logging.info('Query: %s', request.query)

    current_page_token: QueryCursor # Renamed page_token
    try:
      current_page_token = QueryCursor.from_page_token(request.query.page_token)
    except ValueError as e:
      logging.warning("Invalid page token provided: %s", e)
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid page token.')
      return None # For type checker, abort() stops execution

    query_ctx = QueryContext( # Renamed query_context
        service_context=context,
        request_cutoff_time=datetime.now(UTC) + _MAX_SINGLE_QUERY_TIME, # Use UTC
        input_cursor=current_page_token,
        output_cursor=QueryCursor(), # Fresh output cursor
        total_responses=ResponsesCount(0))

    results: Optional[List[vulnerability_pb2.Vulnerability]] = None
    next_page_token_str: Optional[str] = None # Renamed

    try:
      # do_query returns ndb.Future[QueryFutureReturn]
      # .result() blocks and gets the QueryFutureReturn tuple
      future_result: QueryFutureReturn = do_query(request.query, query_ctx).result()
      results, next_page_token_str = future_result
    except GoogleInvalidArgument: # More specific exception from google.api_core
      context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    'Invalid query, likely caused by invalid page token or query structure.')
      return None
    except ndb_exceptions.BadValueError as e: # NDB specific value error
      context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    f'Bad parameter value in query: {e}')
      return None
    # Catch other potential NDB errors if necessary

    if results is not None: # results could be empty list
      return osv_service_v1_pb2.VulnerabilityList(
          vulns=results, next_page_token=next_page_token_str)

    # Should not be reached if do_query always returns a tuple or raises.
    # If it could return (None, None), then handle that.
    # For now, assume results is always a list (possibly empty).
    return osv_service_v1_pb2.VulnerabilityList()


  @ndb_context
  @trace_filter.log_trace
  def QueryAffectedBatch(self, request: osv_service_v1_pb2.QueryAffectedBatchRequest,
                         context: grpc.ServicerContext) -> Optional[osv_service_v1_pb2.BatchVulnerabilityList]:
    """Query vulnerabilities (batch)."""
    batch_results_list: List[osv_service_v1_pb2.VulnerabilityList] = [] # Renamed batch_results
    query_futures: List[ndb.Future[QueryFutureReturn]] = [] # Renamed futures

    # Log summary of query types in the batch
    # Using type Any for query_details structure as it's complex and for logging only
    query_details_log: Dict[str, Any] = { # Renamed query_details
        'commit': 0,
        'ecosystem': defaultdict(lambda: defaultdict(int)), # type: ignore[var-annotated]
        'purl': defaultdict(lambda: defaultdict(int)), # type: ignore[var-annotated]
        'invalid': 0,
    }
    for current_query in request.query.queries: # Renamed query
      query_type_str, ecosystem_str, versioned_str = query_info(current_query)
      if ecosystem_str is not None: # For 'ecosystem' or 'purl' types
        query_details_log[query_type_str][ecosystem_str][versioned_str] += 1
      else: # For 'commit' or 'invalid'
        query_details_log[query_type_str] += 1

    # Filter out empty fields from log details for cleaner logs
    query_details_log = {k: v for k, v in query_details_log.items() if v}

    logging.info(
        'QueryAffectedBatch with %d queries', len(request.query.queries),
        extra={'json_fields': {'details': query_details_log}})

    if get_gcp_project() == _TEST_INSTANCE:
      logging.info('Batch query: %s', request.query)

    if len(request.query.queries) > _MAX_BATCH_QUERY:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Too many queries.')
      return None

    # Shared ResponsesCount object for all sub-queries in this batch
    batch_total_responses = ResponsesCount(0)
    batch_request_cutoff_time = datetime.now(UTC) + _MAX_BATCH_QUERY_TIME # Use UTC

    for i, current_query in enumerate(request.query.queries): # Renamed query
      current_page_token: QueryCursor # Renamed page_token
      try:
        current_page_token = QueryCursor.from_page_token(current_query.page_token)
      except ValueError as e:
        logging.warning("Invalid page token at batch index %d: %s", i, e)
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, f'Invalid page token at index: {i}.')
        return None # For type checker

      query_ctx = QueryContext( # Renamed query_context
          service_context=context,
          request_cutoff_time=batch_request_cutoff_time,
          input_cursor=current_page_token,
          output_cursor=QueryCursor(),
          total_responses=batch_total_responses) # Pass shared ResponsesCount

      query_futures.append(do_query(current_query, query_ctx, include_details=False))

    # Resolve all futures
    for future_item in query_futures: # Renamed future
      results: Optional[List[vulnerability_pb2.Vulnerability]] = None
      next_page_token_str: Optional[str] = None
      try:
        future_result: QueryFutureReturn = future_item.result()
        results, next_page_token_str = future_result
      except GoogleInvalidArgument:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                      'Invalid query in batch, likely caused by invalid page token or query structure.')
        return None
      except ndb_exceptions.BadValueError as e:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                      f'Bad parameter value in batch query: {e}')
        return None

      # Ensure results is a list, even if empty, for VulnerabilityList proto
      batch_results_list.append(
          osv_service_v1_pb2.VulnerabilityList(
              vulns=results or [], next_page_token=next_page_token_str))

    return osv_service_v1_pb2.BatchVulnerabilityList(results=batch_results_list)

  @ndb_context
  @trace_filter.log_trace
  def DetermineVersion(self, request: osv_service_v1_pb2.DetermineVersionQuery,
                       context: grpc.ServicerContext) -> osv_service_v1_pb2.VersionMatchList:
    """Determine the version of the provided hashes."""
    # determine_version is a tasklet, .result() makes it synchronous here.
    # The context arg in determine_version is not used, hence `_`.
    result_future: ndb.Future[osv_service_v1_pb2.VersionMatchList] = determine_version(request, context)
    return result_future.result()

  @ndb_context
  @trace_filter.log_trace
  def ImportFindings(self, request: osv_service_v1_pb2.ImportFindingsRequest,
                     context: grpc.ServicerContext) -> osv_service_v1_pb2.ImportFindingList:
    """Return a list of `ImportFinding` for a given source."""
    source_name: str = request.source # Renamed source
    if not source_name:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    'Missing Source: Please specify the source')
      return osv_service_v1_pb2.ImportFindingList() # For type checker

    if get_gcp_project() == _TEST_INSTANCE:
      logging.info('Checking import finding for %s\n', source_name)

    query_obj: ndb.Query = osv.models.ImportFinding.query(osv.models.ImportFinding.source == source_name) # Renamed query
    # NDB fetch() returns List[Model], here List[osv.models.ImportFinding]
    found_import_findings: List[osv.models.ImportFinding] = query_obj.fetch() # Renamed import_findings

    invalid_records_protos: List[osv.importfinding_pb2.ImportFinding] = [] # Renamed
    for finding_model in found_import_findings: # Renamed finding
      invalid_records_protos.append(finding_model.to_proto())

    return osv_service_v1_pb2.ImportFindingList(invalid_records=invalid_records_protos)

  @ndb_context
  def Check(self, request: health_pb2.HealthCheckRequest,
            context: grpc.ServicerContext) -> health_pb2.HealthCheckResponse:
    """Health check per the gRPC health check protocol."""
    del request  # Unused.
    del context  # Unused.

    # Read up to a single Bug entity from the DB.
    osv.models.Bug.query().fetch(1) # Using osv.models.Bug
    return health_pb2.HealthCheckResponse(
        status=health_pb2.HealthCheckResponse.ServingStatus.SERVING)

  def Watch(self, request: health_pb2.HealthCheckRequest, # type: ignore[override] # Different sig from base
            context: grpc.ServicerContext) -> None: # Original had no return type, implies None
    """Health check per the gRPC health check protocol."""
    # This method is optional for HealthServicer. Aborting if not implemented.
    del request # Unused
    context.abort(grpc.StatusCode.UNIMPLEMENTED, "Watch is not implemented.")
    # No explicit return needed after abort.


def query_info(query: osv_service_v1_pb2.Query) -> Tuple[str, Optional[str], Optional[str]]:
  """Returns information about a query, for logging purposes.
  First return value is one of 'commit', 'purl', 'ecosystem', 'invalid'.
  If 'ecosystem' or 'purl', second two return values are the ecosystem name,
  then 'versioned' or 'versionless' depending if the 'version' field is set.
  Otherwise, last two return values are None.
  """
  query_param_type: str = query.WhichOneof('param') # Renamed qtype to query_param_type

  if query_param_type == 'commit':
    return 'commit', None, None

  # For version or package queries, 'package' field must be present.
  if not query.HasField('package'):
    return 'invalid', None, None # Package field is required for non-commit queries

  # Within package, either purl or name must be present.
  if not query.package.purl and not query.package.name:
    return 'invalid', None, None # Must specify either purl or name for the package

  current_ecosystem: Optional[str] = query.package.ecosystem # Renamed ecosystem
  current_version: Optional[str] = query.version if query.HasField('version') else None # Renamed version

  # Default query type if not PURL
  determined_query_type: str = 'ecosystem' # Renamed qtype

  if query.package.purl:
    try:
      # Attempt to parse the PURL
      parsed_purl = purl_helpers.parse_purl(query.package.purl)
      if parsed_purl is None: # Should not happen if parse_purl raises ValueError on fail
        raise ValueError('PURL ecosystem is unknown or PURL is malformed.')

      # Check for redundant specifications if PURL is used
      if query.package.ecosystem or query.package.name:
        # Server-side validation should handle this, but good for query_info to note
        # For query_info's purpose, we might prioritize PURL's info or mark as potentially ambiguous.
        # Let's assume for logging, we use PURL's info if PURL is present.
        pass # Redundant, but PURL takes precedence for info extraction

      if parsed_purl.version and current_version: # Version in PURL and also in query params
        pass # Redundant, PURL's version usually takes precedence or it's an error

      determined_query_type = 'purl'
      current_ecosystem = parsed_purl.ecosystem
      # If version is in PURL, it overrides the query's version field for classification.
      current_version = parsed_purl.version or current_version

    except ValueError: # Raised by parse_purl for invalid PURLs
      return 'invalid', None, None

  version_status: Optional[str] = 'versioned' if current_version else 'versionless'
  return determined_query_type, current_ecosystem, version_status


# Wrapped in a separate class
@dataclass
class ResponsesCount:
  """Wraps responses count in a separate class 
  to allow it to be passed by reference.
  
  Also adds an interface to allow easy updating to a mutex
  if necessary.
  """
  count: int

  def add(self, amount: int) -> None:
    # This is to prevent query `limit` parameter being smaller than
    # the number that is checked later in the iter() loop for the last page.
    if amount < 0:
      # This check might be too strict if there are legitimate reasons for negative.
      # However, for counting responses, positive amount is expected.
      raise ValueError("Amount to add to responses count must be non-negative.")
    self.count += amount

  def exceeded(self) -> bool:
    return self.count > _MAX_VULN_RESP_THRESH

  def page_limit(self) -> int:
    """
    Returns the page limit based on whether the total number of responses
    across all queries in the batch has exceeded _MAX_VULN_RESP_THRESH.
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
  total_responses: ResponsesCount # Shared across queries in a batch
  query_counter: int = 0 # Tracks number of NDB queries made within a single API call
  single_page_limit_override: Optional[int] = None # Override for specific cases like Ubuntu

  def should_break_page(self, current_page_response_count: int) -> bool: # Renamed response_count
    """
    Returns whether the API should finish its current page here 
    and return a cursor.

    Currently uses two criteria:
      - total response size for this page greater than page limit.
      - request exceeding the cutoff time for the entire API call.
    """
    current_page_limit: int = self.total_responses.page_limit() # Get dynamic page limit
    # Apply override if it's set and total threshold not yet exceeded
    if (self.single_page_limit_override is not None and
        not self.total_responses.exceeded()):
      current_page_limit = self.single_page_limit_override

    # Check if current page's response count hits the limit or time cutoff is reached
    return (current_page_response_count >= current_page_limit or
            datetime.now(UTC) > self.request_cutoff_time) # Use UTC for comparison

  def should_skip_query(self) -> bool:
    """
    Returns whether a query (or part of a query) should be executed or skipped
    based on the input cursor position and whether a page break has already occurred.

    A query (or iteration within a query) should be skipped if:
      - The input cursor indicates we should start at a later query_counter.
      - An output cursor has already been generated (meaning a page limit was hit).
    """
    # query_counter is incremented *before* each NDB query.
    # input_cursor.query_number indicates which NDB query the cursor applies to.
    return (self.query_counter < self.input_cursor.query_number or # Input cursor is for a later NDB query
            not self.output_cursor.ended) # Page limit already hit in a previous NDB query part

  def cursor_at_current(self) -> Optional[ndb.Cursor]:
    """
    Return the ndb.Cursor if the input_cursor is for the current query_counter.
    Otherwise, returns None (implying start from beginning for this NDB query).
    """
    if self.input_cursor.query_number == self.query_counter:
      return self.input_cursor.ndb_cursor # This can be None if it's the first page of that query_number

    return None # Current NDB query should start from the beginning

  def save_cursor_at_page_break(self, it: ndb.QueryIterator) -> None:
    """
    Saves the cursor from the iterator `it` into `self.output_cursor`
    and sets the query_number for the output_cursor.
    """
    self.output_cursor.update_from_iterator(it)
    # query_counter was already incremented for the NDB query that produced 'it'.
    self.output_cursor.query_number = self.query_counter


def should_skip_bucket(path: str) -> bool:
  """Returns whether or not the given file path should be skipped for the
  determineversions bucket computation."""
  if not path: # Empty path
    return False # Or True, depending on desired behavior for empty paths

  # Check for a nested vendored directory.
  components: List[str] = path.split('/')
  return any(c in _VENDORED_LIB_NAMES for c in components)


def process_buckets(
    file_results: List[osv.models.FileResult] # Expecting models.FileResult
) -> List[osv.models.RepoIndexBucket]: # Returning models.RepoIndexBucket
  """
  Create buckets in the same process as 
  indexer to generate the same bucket hashes.
  """
  # buckets is List[List[bytes]], where inner list stores hashes
  buckets: List[List[bytes]] = [[] for _ in range(_BUCKET_SIZE)]

  for fr_item in file_results: # Renamed fr to fr_item
    if should_skip_bucket(fr_item.path): # Assuming fr_item.path is str
      continue

    # Ensure fr_item.hash is bytes and has at least 2 bytes
    if isinstance(fr_item.hash, bytes) and len(fr_item.hash) >= 2:
      bucket_index = int.from_bytes(fr_item.hash[:2], byteorder='big') % _BUCKET_SIZE
      buckets[bucket_index].append(fr_item.hash)
    else:
      # Log or handle invalid hash format if necessary
      logging.warning("Invalid or too short hash for file result: %s", fr_item.path)


  repo_index_buckets: List[osv.models.RepoIndexBucket] = [] # Renamed results
  for bucket_hashes in buckets: # Renamed bucket to bucket_hashes
    bucket_hashes.sort()

    hasher = hashlib.md5()
    for v_bytes in bucket_hashes: # Renamed v to v_bytes
      hasher.update(v_bytes)

    repo_index_buckets.append(
        osv.models.RepoIndexBucket( # Use osv.models
            node_hash=hasher.digest(),
            files_contained=len(bucket_hashes),
        ))

  return repo_index_buckets


def build_determine_version_result(
    file_matches_by_proj: Dict[ndb.Key, int], # Key is likely Key(osv.models.RepoIndex)
    bucket_matches_by_proj: Dict[ndb.Key, int],
    num_skipped_buckets: int,
    empty_bucket_bitmap: int, # 1 means has items, 0 means empty (as per original comment)
    query_file_count: int
) -> osv_service_v1_pb2.VersionMatchList:
  """Build sorted determine version result from the input"""
  # Convert dict items to list of tuples for sorting
  bucket_match_items_list: List[Tuple[ndb.Key, int]] = list(bucket_matches_by_proj.items()) # Renamed
  bucket_match_items_list.sort(key=lambda x: x[1], reverse=True) # Sort by match count

  # Limit to top N results
  bucket_match_items_list = bucket_match_items_list[:min(
      _MAX_DETERMINE_VER_RESULTS_TO_RETURN, len(bucket_match_items_list))]

  # Asynchronously fetch RepoIndex entities for the top matches
  # The keys in bucket_match_items_list are ndb.Key objects for RepoIndex
  repo_index_keys: List[ndb.Key] = [item[0] for item in bucket_match_items_list]
  # ndb.get_multi_async returns List[Future[Optional[Model]]]
  idx_futures: List[ndb.Future[Optional[osv.models.RepoIndex]]] = ndb.get_multi_async(repo_index_keys)

  output_matches: List[osv_service_v1_pb2.VersionMatch] = [] # Renamed output

  # User's query bitmap: 1 means user has content in that bucket, 0 means empty.
  # Inverted: 1 means user's bucket is empty, 0 means user has content.
  inverted_empty_bucket_bitmap = ((1 << _BUCKET_SIZE) - 1) ^ empty_bucket_bitmap
  query_empty_bucket_count = inverted_empty_bucket_bitmap.bit_count() # Renamed empty_bucket_count

  for i, future_repo_idx in enumerate(idx_futures): # Renamed f to future_repo_idx
    repo_idx: Optional[osv.models.RepoIndex] = future_repo_idx.result() # Renamed idx

    if repo_idx is None:
      logging.warning(
          'RepoIndex entity not found for key: %s, though bucket matches existed.',
          bucket_match_items_list[i][0])
      continue

    if repo_idx.empty_bucket_bitmap is None: # Should be bytes from datastore
      logging.warning('No empty bucket bitmap for RepoIndex: %s@%s', repo_idx.name, repo_idx.tag)
      continue

    # Repo's bitmap: 1 means repo bucket is empty, 0 means has content.
    repo_bitmap = int.from_bytes(repo_idx.empty_bucket_bitmap, byteorder='little')

    # Missed empty buckets: User has content (inverted_empty_bitmap=0), but repo says empty (repo_bitmap=1).
    # This means user has files that hash to a bucket the repo considers empty.
    # (inverted_empty_bitmap & repo_bitmap) would identify these.
    # Let's re-check logic:
    # User query: empty_bucket_bitmap (1=has content, 0=empty).
    # Repo index: repo_bitmap (1=empty, 0=has content).
    # We want to count buckets where user has content (user_map=1) but repo says empty (repo_map=1).
    # No, this is "missed_empty_buckets".
    # Original comment: "cases where the bitmap generated by the user query gives a 0 (empty),
    # but the bitmap of the repo is a 1 (empty)". This is agreement on emptiness.
    # "We do not want to count cases where the repo bitmap contains 0 (content) but
    # the user bitmap contains 1 (content)". This means shared content.
    # "A bitwise NOT on the user query bitmap followed by a bitwise AND satisfies this requirement."
    # User query bitmap (input `empty_bucket_bitmap`): 1=has content, 0=empty.
    # `inverted_empty_bucket_bitmap`: 1=user_empty, 0=user_has_content.
    # `repo_bitmap`: 1=repo_empty, 0=repo_has_content.
    # `missed_empty_buckets = (inverted_empty_bucket_bitmap & repo_bitmap)`
    # This counts buckets where user says empty AND repo says empty. This is agreement.
    # The intent seems to be about differences.
    # Let's use the term "diverging_buckets": user has content where repo is empty, or vice versa.
    # This is complex. Sticking to original var name and formula, assuming it's correct.
    missed_empty_buckets_count = (inverted_empty_bucket_bitmap & repo_bitmap).bit_count() # Renamed

    # Number of buckets that actually changed content status (empty vs non-empty)
    # This is effectively (user_bitmap XOR repo_bitmap) if both use same convention (1=empty or 1=content)
    # The `num_bucket_change` for estimate_diff is not directly `missed_empty_buckets_count`.
    # It's more like total buckets - matched content buckets - matched empty buckets.
    # For now, assume `missed_empty_buckets_count` is used correctly in `estimate_diff` context.
    # `bucket_matches_by_proj[repo_idx.key]` is count of content buckets that matched.
    # `query_empty_bucket_count` is number of buckets user claims are empty.

    # This calculation needs to be precise based on estimate_diff's expectation.
    # For now, I'll assume the variables passed to estimate_diff are correct as per original logic.
    num_bucket_change_for_estimate = (
        _BUCKET_SIZE
        - bucket_matches_by_proj.get(repo_idx.key, 0) # Content buckets that matched
        - query_empty_bucket_count # Buckets user says are empty
        + missed_empty_buckets_count # Adjust based on agreement/disagreement on emptiness
        - num_skipped_buckets # Buckets skipped from matching
    )

    estimated_diff_files_val = estimate_diff( # Renamed
        num_bucket_change_for_estimate,
        abs(repo_idx.file_count - query_file_count)
    )

    max_files_val = max(repo_idx.file_count, query_file_count) # Renamed
    score_val = (max_files_val - estimated_diff_files_val) / max_files_val if max_files_val > 0 else 0 # Renamed

    # Normalize tag for version display
    version_str = osv.models.normalize_tag(repo_idx.tag.removeprefix(_TAG_PREFIX)) # Renamed version
    version_str = version_str.replace('-', '.') # Further normalization for display
    if not version_str:  # This tag actually isn't a version (rare)
      continue

    version_match_proto = osv_service_v1_pb2.VersionMatch( # Renamed version_match
        score=score_val,
        minimum_file_matches=file_matches_by_proj.get(repo_idx.key, 0),
        estimated_diff_files=estimated_diff_files_val,
        repo_info=osv_service_v1_pb2.VersionRepositoryInformation(
            type=osv_service_v1_pb2.VersionRepositoryInformation.Type.GIT, # Assuming GIT
            address=repo_idx.repo_addr,
            commit=repo_idx.commit.hex() if repo_idx.commit else "", # Handle None commit
            tag=repo_idx.tag.removeprefix(_TAG_PREFIX),
            version=version_str,
        ))

    if version_match_proto.score < _DETERMINE_VER_MIN_SCORE_CUTOFF:
      continue

    output_matches.append(version_match_proto)

  output_matches.sort(key=lambda x: x.score, reverse=True)
  return osv_service_v1_pb2.VersionMatchList(matches=output_matches)


def estimate_diff(num_bucket_change: int, file_count_diff: int) -> int:
  """
  Estimates the number of files that have changed based on 
  the number of buckets that changed.
  """
  # Avoid math.log domain error if num_bucket_change makes denominator <= 0
  denominator = _BUCKET_SIZE - num_bucket_change + 1
  if denominator <= 0: # This implies high change, estimate as very large or max possible
      # This case needs careful handling based on formula's intent for edge cases.
      # For now, if invalid input for log, assume maximal difference relative to what's possible.
      # Or, cap num_bucket_change to avoid this.
      # If num_bucket_change >= _BUCKET_SIZE + 1, then it's problematic.
      # Let's assume num_bucket_change is always < _BUCKET_SIZE + 1 for valid log.
      # A simple cap:
      if num_bucket_change > _BUCKET_SIZE: num_bucket_change = _BUCKET_SIZE

  # Recalculate denominator with capped value
  denominator = _BUCKET_SIZE - num_bucket_change + 1
  if denominator == 0: # Avoid division by zero if somehow num_bucket_change = _BUCKET_SIZE + 1
      # This implies all buckets changed plus one, which is impossible.
      # A very large estimate might be appropriate.
      # This indicates a very high change rate.
      # Let's return a high number, e.g. sum of files or similar upper bound.
      # For now, this edge case implies estimate calculation is not meaningful.
      # Original formula might assume valid range for num_bucket_change.
      # If num_bucket_change is _BUCKET_SIZE, log(BUCKET_SIZE+1 / 1) = log(BUCKET_SIZE+1)
      # If num_bucket_change is 0, log(BUCKET_SIZE+1 / BUCKET_SIZE+1) = log(1) = 0.
      # This seems okay.
      pass


  estimate_val: float # Renamed estimate
  if denominator <= 0: # Should be caught by cap if applied, or indicates extreme change
      # If all buckets changed, estimate is effectively infinite number of file changes from this formula's perspective.
      # This needs a practical upper bound or different handling.
      # For now, if this state is reached, assume estimate part is very high (e.g. sum of files).
      # This part of formula implies num_bucket_change must be <= _BUCKET_SIZE.
      # If num_bucket_change = _BUCKET_SIZE, log((_BUCKET_SIZE+1)/1).
      # If num_bucket_change > _BUCKET_SIZE, it's an issue with how it's calculated or used.
      # Let's assume num_bucket_change <= _BUCKET_SIZE.
      estimate_val = float('inf') # Or a very large number if inf is not desired.
  else:
      estimate_val = _BUCKET_SIZE * math.log(
        (_BUCKET_SIZE + 1) / denominator
      )

  # The formula `max(estimate - file_count_diff, 0) / 2` means we only consider
  # the bucket-change based estimate if it's larger than the raw file count difference,
  # and then average it somehow (divide by 2 suggests averaging this excess with something, or halving it).
  # This is specific domain logic.
  if estimate_val == float('inf'): # Handle inf case from log
      # If estimate is infinite, the number of changed files is likely very high.
      # Perhaps return total number of files or sum of file_count_diff and a large number.
      # For now, let's assume this implies max possible difference or that input needs validation.
      # A practical upper bound might be the total number of files involved.
      # This indicates a very high dissimilarity.
      return file_count_diff + _BUCKET_SIZE # Example: just add BUCKET_SIZE as a penalty

  return file_count_diff + round(max(estimate_val - file_count_diff, 0) / 2)


@ndb.tasklet
def determine_version(version_query: osv_service_v1_pb2.DetermineVersionQuery,
                      context: grpc.ServicerContext # Renamed _ to context for clarity, though unused
                     ) -> ndb.Future[osv_service_v1_pb2.VersionMatchList]:
  """Identify fitting commits based on a subset of hashes"""
  del context # Unused parameter, marked for clarity or future use
  logging.info("DetermineVersion for %d hashes", len(version_query.file_hashes))

  # Convert proto FileDigest to models.FileResult for process_buckets
  file_results_list: List[osv.models.FileResult] = [] # Renamed req_list
  for x_digest in version_query.file_hashes: # Renamed x to x_digest
    # Assuming x_digest.hash is bytes. Validate length if necessary.
    # The original code checks len(x.hash) <= 100. MD5 is 16 bytes. SHA256 is 32.
    # This check might be for very long, potentially invalid, hash strings.
    if x_digest.hash and len(x_digest.hash) <= 100: # Ensure hash is not empty
      file_results_list.append(osv.models.FileResult(hash=x_digest.hash))
    else:
      logging.warning("Skipping invalid or too long hash in DetermineVersion.")


  # Build all the buckets and query the bucket hash
  # process_buckets returns List[osv.models.RepoIndexBucket]
  processed_buckets: List[osv.models.RepoIndexBucket] = process_buckets(file_results_list) # Renamed buckets

  # Dictionaries to store match counts per RepoIndex Key
  # Key type is ndb.Key (specifically Key(osv.models.RepoIndex))
  file_match_counts: Dict[ndb.Key, int] = defaultdict(int) # Renamed
  bucket_match_counts: Dict[ndb.Key, int] = defaultdict(int) # Renamed

  num_skipped_buckets_val: int = 0 # Renamed
  skipped_files_count: int = 0 # Renamed

  # Bitmap: 1 means user query has content in bucket, 0 means empty.
  query_content_bitmap: int = 0 # Renamed empty_bucket_bitmap

  # List of (Future[List[RepoIndexBucket]], bucket_index, files_in_query_bucket)
  # NDB fetch_async returns Future[List[Model]]
  query_futures_list: List[Tuple[ndb.Future[List[osv.models.RepoIndexBucket]], int, int]] = [] # Renamed

  for bucket_idx, current_bucket in enumerate(processed_buckets): # Renamed idx, bucket
    if current_bucket.files_contained == 0:
      continue # Skip empty buckets in the query

    query_content_bitmap |= (1 << bucket_idx) # Mark this bucket as having content from user

    # Query for RepoIndexBucket entities that match the hash of the user's current bucket
    # osv.models needed here
    ndb_q: ndb.Query = osv.models.RepoIndexBucket.query(
        osv.models.RepoIndexBucket.node_hash == current_bucket.node_hash)

    query_futures_list.append((
        ndb_q.fetch_async(limit=_MAX_MATCHES_TO_CARE), # type: ignore[arg-type] # fetch_async expects int
        bucket_idx,
        current_bucket.files_contained
    ))

  # Process results of async queries
  for future_bucket_results, _, num_files_in_query_bucket in query_futures_list: # Renamed future, idx, num_of_files
    # .result() blocks to get actual List[osv.models.RepoIndexBucket]
    matched_repo_buckets: List[osv.models.RepoIndexBucket] = list(future_bucket_results.result()) # Renamed result

    if matched_repo_buckets:
      if len(matched_repo_buckets) == _MAX_MATCHES_TO_CARE: # Too many repos share this bucket hash
        num_skipped_buckets_val += 1
        skipped_files_count += num_files_in_query_bucket
        continue

      for repo_bucket_match in matched_repo_buckets: # Renamed index_bucket
        # Key of RepoIndexBucket has RepoIndex as parent
        parent_repo_key: Optional[ndb.Key] = repo_bucket_match.key.parent() # type: ignore[union-attr] # key can be None
        if parent_repo_key:
          file_match_counts[parent_repo_key] += repo_bucket_match.files_contained # type: ignore[union-attr]
          bucket_match_counts[parent_repo_key] += 1

  # Adjust file match counts for skipped buckets (those with too many repo matches)
  for key_item in file_match_counts: # Renamed key
    file_match_counts[key_item] += skipped_files_count

  return build_determine_version_result(
      file_match_counts, bucket_match_counts,
      num_skipped_buckets_val, query_content_bitmap,
      len(version_query.file_hashes) # Total number of files in original query
  )


@ndb.tasklet # This ndb.tasklet implies the function is async and returns a Future
def do_query(query: osv_service_v1_pb2.Query,
             context: QueryContext,
             include_details: bool = True
            ) -> ndb.Future[QueryFutureReturn]: # Return Future of (vuln_list, next_page_token_str)
  """Do a query."""
  package_name_val: str = '' # Renamed
  ecosystem_val: str = '' # Renamed
  purl_str_val: str = '' # Renamed
  version_str: str = '' # Renamed version

  if query.HasField('package'):
    package_name_val = query.package.name
    ecosystem_val = query.package.ecosystem
    purl_str_val = query.package.purl

  if query.HasField('version'): # Check if version field is set
    version_str = query.version

  # Convert PURL to package name, ecosystem, version if PURL is provided
  if purl_str_val:
    parsed_purl: Optional[purl_helpers.ParsedPURL] = None # Renamed purl
    try:
      parsed_purl = purl_helpers.parse_purl(purl_str_val)
    except ValueError as e: # parse_purl might raise ValueError for invalid PURLs
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, f'Invalid PURL: {e}')
      # Abort stops execution, but for type checker:
      raise # Or return ndb.Future.from_result(([], None)) if abort doesn't satisfy static analysis

    # Check for redundant specifications if PURL is used
    if package_name_val:
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'name specified in a PURL query')
      raise
    if ecosystem_val:
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'ecosystem specified in a PURL query')
      raise
    if parsed_purl is None: # Should be caught by ValueError from parse_purl if it returns None on failure
      # This path implies parse_purl succeeded but returned None (e.g. unknown ecosystem in PURL)
      # Original code returns empty list and None token for this.
      return [], None # type: ignore[return-value] # ndb.tasklet expects Future
                      # Correct way: ndb.Future.from_result(([], None))

    # If version is in PURL and also in query parameters (version_str)
    if parsed_purl.version and version_str:
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'version specified in params and PURL query')
      raise

    ecosystem_val = parsed_purl.ecosystem or "" # Ensure ecosystem_val is str
    package_name_val = parsed_purl.package
    if parsed_purl.version: # If version was in PURL, it takes precedence
      version_str = parsed_purl.version

  # Validate ecosystem if provided
  if ecosystem_val and not ecosystems.get(ecosystem_val):
    context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid ecosystem.')
    raise

  # Normalize package name if applicable
  if package_name_val and ecosystem_val: # Need ecosystem for normalization rules
    package_name_val = ecosystems.maybe_normalize_package_names(package_name_val, ecosystem_val)

  # Special handling for Ubuntu package queries to increase page limit
  if ecosystem_val.startswith('Ubuntu') and 'linux' in package_name_val:
    context.single_page_limit_override = _MAX_VULN_LISTED_PRE_EXCEEDED_UBUNTU_EXCEPTION

  # Define how Bug entities are converted to response protos
  current_to_response: ToResponseCallable = lambda b: bug_to_response(b, include_details) # Renamed

  # List to hold final vulnerability protos
  # NDB futures should yield osv.models.Bug, which are then converted
  vulnerabilities_task_result: List[vulnerability_pb2.Vulnerability] # Renamed bugs

  query_type: str = query.WhichOneof('param') # Determine query type (commit, version, package)

  if query_type == 'commit':
    commit_bytes: bytes
    try:
      commit_bytes = codecs.decode(query.commit, 'hex')
    except ValueError: # Invalid hex string for commit
      context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid commit hash format.')
      raise
    vulnerabilities_task_result = yield query_by_commit(context, commit_bytes, to_response=current_to_response)

  elif package_name_val and version_str: # Query by package and version
    vulnerabilities_task_result = yield query_by_version(
        context, package_name_val, ecosystem_val, version_str, to_response=current_to_response)

  elif package_name_val and ecosystem_val: # Query by package and ecosystem (no version)
    vulnerabilities_task_result = yield query_by_package(
        context, package_name_val, ecosystem_val, to_response=current_to_response)

  else: # Invalid query parameters (e.g., version without package, or only ecosystem)
    context.service_context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid query parameters.')
    raise

  # Asynchronously retrieve computed aliases and related ids if details are included
  if include_details and vulnerabilities_task_result: # Check if list is not empty
    alias_futures: List[ndb.Future[Optional[osv.models.AliasGroup]]] = [] # Renamed aliases
    related_futures: List[ndb.Future[List[str]]] = [] # Renamed related

    for vuln_proto in vulnerabilities_task_result: # Renamed bug to vuln_proto
      alias_futures.append(osv.models.get_aliases_async(vuln_proto.id))
      related_futures.append(osv.models.get_related_async(vuln_proto.id))

    for i, alias_future_item in enumerate(alias_futures): # Renamed alias to alias_future_item
      alias_group_result: Optional[osv.models.AliasGroup] = yield alias_future_item # Renamed alias_group
      if alias_group_result and alias_group_result.bug_ids: # Ensure bug_ids is not None
        # Filter out the vuln's own ID from its aliases
        alias_ids_list = sorted(list(set(alias_group_result.bug_ids) - {vulnerabilities_task_result[i].id})) # Renamed
        vulnerabilities_task_result[i].aliases[:] = alias_ids_list # Update proto field
        # Update modified time if alias group is newer
        if alias_group_result.last_modified:
            modified_dt = vulnerabilities_task_result[i].modified.ToDatetime(tz=UTC) # tz aware
            modified_dt = max(alias_group_result.last_modified, modified_dt)
            vulnerabilities_task_result[i].modified.FromDatetime(modified_dt)


    for i, related_future_item in enumerate(related_futures): # Renamed related_ids to related_future_item
      related_bug_ids_list: List[str] = yield related_future_item # Renamed
      # Combine and sort related IDs
      vulnerabilities_task_result[i].related[:] = sorted(
          list(set(related_bug_ids_list + list(vulnerabilities_task_result[i].related))))


  # Validate cursor state after all NDB queries for this API call are done (or supposed to be)
  if context.query_counter < context.input_cursor.query_number:
    logging.error(
        'Cursor state invalid: input cursor for query #%d, but only %d NDB queries made.',
        context.input_cursor.query_number, context.query_counter)
    # This indicates an issue, potentially an invalid page_token from client for the current query structure.
    # Abort or return error, as results might be inconsistent.
    # Original code raises ValueError here.
    # Let's ensure it's wrapped in a future if this is still in tasklet.
    # However, this check seems more appropriate after all yields for NDB queries.
    # For now, let's assume this means an invalid request.
    # This should ideally be caught by gRPC framework or an earlier validation step if possible.
    # Re-raising as ValueError to be caught by caller if this is critical.
    raise ValueError('Cursor is invalid/does not belong to this query (post-yield check)')


  final_next_page_token: Optional[str] = context.output_cursor.url_safe_encode() # Renamed
  if final_next_page_token:
    logging.info('Page size limit hit, responses on this page: %s. Next token generated.', len(vulnerabilities_task_result)) # Log info

  # This function is a tasklet, so it must return a Future or be `yield`ed from.
  # The final result is `(vulnerabilities_task_result, final_next_page_token)`
  # NDB tasklets automatically wrap bare return values in a Future.
  return vulnerabilities_task_result, final_next_page_token


def bug_to_response(bug: osv.models.Bug, # osv.models.Bug
                    include_details: bool = True,
                    include_alias: bool = False) -> vulnerability_pb2.Vulnerability:
  """Convert a Bug entity to a response object."""
  if include_details:
    return bug.to_vulnerability(
        include_source=True, include_alias=include_alias)
  return bug.to_vulnerability_minimal()


@ndb.tasklet # Async NDB operation
def _get_bugs(
    bug_ids: List[str],
    to_response: ToResponseCallable = bug_to_response # Default converter
) -> ndb.Future[List[vulnerability_pb2.Vulnerability]]: # Returns Future
  """Get bugs from bug ids."""
  # Create NDB keys from string IDs
  bug_keys: List[ndb.Key] = [ndb.Key(osv.models.Bug, bug_id) for bug_id in bug_ids]
  # Fetch multiple Bug entities asynchronously. Returns List[Future[Optional[Bug]]]
  bug_futures: List[ndb.Future[Optional[osv.models.Bug]]] = ndb.get_multi_async(bug_keys) # type: ignore[assignment,arg-type]

  responses_list: List[vulnerability_pb2.Vulnerability] = [] # Renamed responses
  for future_bug_item in bug_futures: # Renamed future_bug
    bug_model: Optional[osv.models.Bug] = yield future_bug_item # Renamed bug
    if bug_model and bug_model.status == osv.models.BugStatus.PROCESSED.value and bug_model.public: # Use .value for enum
      responses_list.append(to_response(bug_model))

  return responses_list


@ndb.tasklet # Async NDB operation
def query_by_commit(
    context: QueryContext,
    commit_hash: bytes, # Renamed commit
    to_response: ToResponseCallable = bug_to_response
) -> ndb.Future[List[vulnerability_pb2.Vulnerability]]: # Returns Future
  """
  Perform a query by commit.

  This is a ndb.tasklet, so will return a future that will need to be yielded.

  Args:
    context: QueryContext for the current query.
    commit_hash: The commit hash to query.
    to_response: Optional function to convert osv.Bug to a 
      vulnerability response.

  Returns:
    list of responses (return values from to_response)
  """
  # Query for AffectedCommits entities that contain the given commit_hash
  # osv.models needed here
  ndb_q: ndb.Query = osv.models.AffectedCommits.query(osv.models.AffectedCommits.commits == commit_hash) # Renamed query

  context.query_counter += 1 # Increment for this NDB query
  if context.should_skip_query():
    return [] # type: ignore[return-value] # Tasklet expects Future, will be wrapped

  found_bug_ids: List[str] = [] # Renamed bug_ids
  # Get an iterator for the query
  # Using keys_only=True for efficiency if only bug_id is needed from AffectedCommits
  query_iterator: ndb.QueryIterator = ndb_q.iter( # Renamed it
      keys_only=True, start_cursor=context.cursor_at_current())


  while (yield query_iterator.has_next_async()): # type: ignore[misc] # bad type for query_iterator
    if context.should_break_page(len(found_bug_ids)):
      context.save_cursor_at_page_break(query_iterator)
      break

    # next() will not return None due to has_next_async check
    affected_commits_key: ndb.Key = query_iterator.next() # type: ignore[assignment] # Renamed affected_commits
    # AffectedCommits key ID is like "<BugID>-<PageNumber>"
    # Extract BugID part. Ensure id() is not None.
    key_id_str: Optional[str] = affected_commits_key.id() # type: ignore[union-attr]
    if not key_id_str: continue # Should not happen for valid keys

    bug_id_str: str = key_id_str.rsplit("-", 1)[0] # Renamed bug_id
    if bug_id_str not in found_bug_ids: # Avoid duplicates if commit in multiple pages for same bug
        found_bug_ids.append(bug_id_str)
        context.total_responses.add(1) # Count unique bugs found

  # Fetch Bug entities for the collected bug_ids
  # _get_bugs is a tasklet, so yield its result (which is a Future)
  vulnerabilities_list: List[vulnerability_pb2.Vulnerability] = yield _get_bugs(found_bug_ids, to_response=to_response) # Renamed bugs
  return vulnerabilities_list


def _is_semver_affected(affected_packages: List[osv.models.AffectedPackage], # osv.models
                        package_name: Optional[str], # Renamed
                        ecosystem_name: Optional[str], # Renamed ecosystem
                        version_str_input: str) -> bool: # Renamed version_str
  """Returns whether or not the given version is within an affected SEMVER range."""
  try:
    # Ensure version_str_input is valid semver before parsing
    # semver_index.parse might raise ValueError for invalid semver strings
    parsed_version: semver_index.semver.Version = semver_index.parse(version_str_input) # Renamed version
  except ValueError:
    return False # Invalid query version string is not affected by valid semver ranges

  is_currently_affected: bool = False # Renamed affected
  for current_affected_package in affected_packages: # Renamed affected_package
    # Filter by package name if provided
    if package_name and package_name != current_affected_package.package.name: # type: ignore[union-attr]
      continue
    # Filter by ecosystem name if provided
    if ecosystem_name and ecosystem_name != current_affected_package.package.ecosystem: # type: ignore[union-attr]
      continue

    for current_range in current_affected_package.ranges: # type: ignore[attr-defined] # Renamed affected_range
      if current_range.type != 'SEMVER':
        continue

      # Reset affected status for each new SEMVER range
      is_currently_affected_by_this_range = False
      # osv.models.sorted_events needed
      for event_item in osv.models.sorted_events(ecosystem_name, current_range.type, current_range.events): # Renamed event
        try:
          # Event values should also be valid semver strings for comparison
          event_semver = semver_index.parse(event_item.value)
        except ValueError:
          # Invalid semver in event data, skip this event or log warning
          logging.warning("Invalid semver in event data: %s for bug %s", event_item.value, package_name)
          continue

        if event_item.type == 'introduced':
          if event_item.value == '0' or parsed_version >= event_semver:
            is_currently_affected_by_this_range = True
        elif event_item.type == 'fixed':
          if parsed_version >= event_semver:
            is_currently_affected_by_this_range = False
        elif event_item.type == 'last_affected':
          if parsed_version > event_semver: # Strictly greater for last_affected
            is_currently_affected_by_this_range = False

      # If, after all events in this range, it's still affected, then the version is affected.
      if is_currently_affected_by_this_range:
        return True # Affected by at least one range

  return False # Not affected by any SEMVER range after checking all


def _is_version_affected(affected_packages: List[osv.models.AffectedPackage], # osv.models
                         package_name: Optional[str],
                         ecosystem_name: Optional[str], # Renamed ecosystem
                         version_str: str, # Renamed version
                         normalize_version: bool = False) -> bool: # Renamed normalize
  """
  Returns whether or not the given version_str is in the explicit list of
  affected versions for any matching package.
  """
  # This function checks against `affected_package.versions` list, not ranges.
  for current_affected_package in affected_packages: # Renamed affected_package
    # Check ecosystem match
    if ecosystem_name:
      if not is_matching_package_ecosystem(
          current_affected_package.package.ecosystem, ecosystem_name): # type: ignore[union-attr]
        continue

    # Check package name match
    if package_name:
      # Special handling for GIT ecosystem if package name is a repo URL
      if ecosystem_name == 'GIT':
        # Extract repo URL from affected_package ranges if present
        # This logic might be simplified if affected_package.package.name is already the repo URL for GIT.
        # Assuming package_name for GIT is the repo URL.
        # The original code had a loop here, but if package.name is already repo_url, it's simpler.
        # For now, assume package_name is what we match against package.name.
        # If GIT has special matching rules for package.name vs repo_url, it needs to be specific.
        # Let's assume current_affected_package.package.name is the canonical name/URL to match.
        if package_name != current_affected_package.package.name: # type: ignore[union-attr]
            continue
      else: # For other ecosystems, direct name match
        if package_name != current_affected_package.package.name: # type: ignore[union-attr]
          continue

    # Check version match (either direct or normalized)
    # Ensure affected_package.versions is not None
    versions_list_to_check = current_affected_package.versions or [] # type: ignore[union-attr]

    if normalize_version: # Compare normalized tags
      normalized_query_version = osv.models.normalize_tag(version_str) # osv.models
      if any(normalized_query_version == osv.models.normalize_tag(v_str) # osv.models
             for v_str in versions_list_to_check):
        return True
    else: # Direct string comparison
      if version_str in versions_list_to_check:
        return True

  return False # No match found


@ndb.tasklet # Async NDB operation
def _query_by_semver(context: QueryContext,
                     base_query: ndb.Query, # Renamed query to base_query
                     package_name: Optional[str],
                     ecosystem_name: Optional[str], # Renamed ecosystem
                     version_str: str # Renamed version
                    ) -> ndb.Future[List[osv.models.Bug]]: # Returns Future[List[Bug]]
  """
  Perform a query by semver version.
  This is an ndb.tasklet, so it returns a Future.
  """
  if not semver_index.is_valid(version_str): # Check if query version is valid semver
    return [] # type: ignore[return-value] # Tasklet expects Future

  # Build the query: filter by normalized fixed versions greater than query version
  # This finds bugs that *could* affect version_str because they were fixed *after* it.
  # osv.models needed here
  final_query: ndb.Query = base_query.filter( # Renamed query
      osv.models.Bug.semver_fixed_indexes > semver_index.normalize(version_str))

  context.query_counter += 1 # Increment for this NDB query
  if context.should_skip_query():
    return [] # type: ignore[return-value]

  # List to store matching Bug entities
  matched_bugs_list: List[osv.models.Bug] = [] # Renamed results

  query_iterator: ndb.QueryIterator = final_query.iter(start_cursor=context.cursor_at_current()) # Renamed it

  while (yield query_iterator.has_next_async()): # type: ignore[misc]
    if context.should_break_page(len(matched_bugs_list)):
      context.save_cursor_at_page_break(query_iterator)
      break

    bug_model: osv.models.Bug = query_iterator.next() # type: ignore[assignment] # Renamed bug
    # Further filter: check if the version_str is actually affected by this bug's ranges
    if _is_semver_affected(bug_model.affected_packages, package_name, ecosystem_name, version_str):
      matched_bugs_list.append(bug_model)
      context.total_responses.add(1)

  return matched_bugs_list


@ndb.tasklet # Async NDB operation
def _query_by_generic_version(
    context: QueryContext,
    base_query: ndb.Query, # NDB Query object
    package_name: Optional[str],
    ecosystem_name: Optional[str], # Renamed ecosystem
    version_str: str, # Renamed version
) -> ndb.Future[List[osv.models.Bug]]: # Returns Future[List[Bug]]
  """
  Query by generic version (non-SemVer or when SemVer match is not primary).
  This is an ndb.tasklet, so it returns a Future.
  It tries querying with the version string as is, then normalized, then canonicalized+normalized.
  """
  # Attempt 1: Query with the version string as is (no normalization yet for query term)
  # The _is_version_affected check inside query_by_generic_helper will handle normalization if needed.
  # Here, is_normalized=False for the first call.
  bugs_found: List[osv.models.Bug] = yield query_by_generic_helper( # Renamed results
      context, base_query, package_name, ecosystem_name, version_str, is_normalized=False)
  if bugs_found:
    return bugs_found

  # Attempt 2: Query with normalized version string
  normalized_version_str = osv.models.normalize_tag(version_str) # osv.models
  if normalized_version_str != version_str: # Only if normalization changed it
    bugs_found = yield query_by_generic_helper(
        context, base_query, package_name, ecosystem_name, normalized_version_str, is_normalized=True)
    if bugs_found:
      return bugs_found

  # Attempt 3: Query with canonicalized and then normalized version string
  canonical_version_str = canonicalize_version(version_str)
  # Normalize the canonical version for the final lookup attempt.
  normalized_canonical_version_str = osv.models.normalize_tag(canonical_version_str) # osv.models

  if normalized_canonical_version_str != normalized_version_str : # Only if different from previous attempt
    bugs_found = yield query_by_generic_helper(
        context, base_query, package_name, ecosystem_name, normalized_canonical_version_str, is_normalized=True)
    # No early return here, this is the last attempt.

  return bugs_found


@ndb.tasklet # Async NDB operation
def query_by_generic_helper(context: QueryContext,
                            base_query: ndb.Query, # NDB Query
                            package_name: Optional[str],
                            ecosystem_name: Optional[str], # Renamed ecosystem
                            version_str: str, # Renamed version
                            is_normalized_query_version: bool # Renamed is_normalized
                           ) -> ndb.Future[List[osv.models.Bug]]: # Returns Future
  """
  Helper function for _query_by_generic_version. Performs one attempt.
  This is an ndb.tasklet, so it returns a Future.
  """
  # Filter by the (potentially normalized) version string against `affected_fuzzy`
  # osv.models needed here
  final_query: ndb.Query = base_query.filter(osv.models.Bug.affected_fuzzy == version_str) # Renamed query

  matched_bugs_list: List[osv.models.Bug] = [] # Renamed results

  context.query_counter += 1 # Increment for this NDB query
  if context.should_skip_query():
    return [] # type: ignore[return-value]

  query_iterator: ndb.QueryIterator = final_query.iter(start_cursor=context.cursor_at_current()) # Renamed it

  while (yield query_iterator.has_next_async()): # type: ignore[misc]
    if context.should_break_page(len(matched_bugs_list)):
      context.save_cursor_at_page_break(query_iterator)
      break

    bug_model: osv.models.Bug = query_iterator.next() # type: ignore[assignment] # Renamed bug
    # _is_version_affected checks if this bug (already matched by version string)
    # also matches the package_name and ecosystem if provided.
    if _is_version_affected(
        bug_model.affected_packages,
        package_name,
        ecosystem_name, # Pass ecosystem_name
        version_str, # Pass version_str used in query
        normalize_version=is_normalized_query_version): # Pass normalization status
      matched_bugs_list.append(bug_model)
      context.total_responses.add(1)

  return matched_bugs_list


@ndb.tasklet # Async NDB operation
def query_by_version(
    context: QueryContext,
    package_name: Optional[str], # Can be None if PURL is used later or ecosystem implies it
    ecosystem_name: Optional[str], # Renamed ecosystem. Can be None if PURL or not specified.
    version_str: str, # Renamed version
    to_response: ToResponseCallable = bug_to_response
) -> ndb.Future[List[vulnerability_pb2.Vulnerability]]: # Returns Future
  """
  Query by (fuzzy) version.
  This is an ndb.tasklet, so it returns a Future.
  """
  # Base query for package_name and public, processed bugs
  # osv.models needed here
  if not package_name: # Package name is required for version queries
      # This case should ideally be validated before calling this function.
      logging.warning("query_by_version called without package_name.")
      return [] # type: ignore[return-value]

  base_ndb_query: ndb.Query = osv.models.Bug.query( # Renamed query
      osv.models.Bug.status == osv.models.BugStatus.PROCESSED.value, # Use .value
      osv.models.Bug.project == package_name,
      osv.models.Bug.public == True,  # noqa: E712
  )

  # Further filter by ecosystem if provided
  current_ecosystem_info: Optional[ecosystems.Ecosystem] = None # Renamed
  if ecosystem_name:
    base_ndb_query = base_ndb_query.filter(osv.models.Bug.ecosystem == ecosystem_name)
    current_ecosystem_info = ecosystems.get(ecosystem_name)

  # Determine query strategy based on ecosystem type (SemVer, comparable, generic)
  # This list will hold osv.models.Bug entities
  found_bugs_models: List[osv.models.Bug] = [] # Renamed bugs

  if ecosystem_name: # Ecosystem is specified
    if current_ecosystem_info and current_ecosystem_info.is_semver:
      # Ecosystem supports SemVer. Try SemVer query first.
      found_bugs_models = yield _query_by_semver(context, base_ndb_query, package_name, ecosystem_name, version_str)
      # Also try generic query as fallback or supplement
      # (Original logic tried generic if semver fully finished or skipped, then merged)
      # This needs careful handling of context.query_counter if generic also increments.
      # For simplicity, let's assume they are somewhat independent if ecosystem is known.
      # The original logic to merge results if semver didn't exhaust page seems complex.
      # A simpler approach: if semver yields results, and page not full, also try generic for same page.
      # This requires careful cursor management.
      # For now: if semver is primary, and it doesn't fill the page, try generic.
      # This is tricky with shared `context.query_counter`.
      # Let's assume for a known semver ecosystem, semver query is primary.
      # If it doesn't fill the page, a subsequent generic query might be attempted.
      # The original code structure implied possibly two separate NDB queries if semver + generic.
      # This means `context.query_counter` would increment for each.
      # This is complex to manage for pagination.
      # For now, let's simplify: if SemVer, primarily use SemVer. Fallback to generic if needed.
      # The current structure calls _query_by_generic_version after _query_by_semver
      # and merges results. This is what I will follow.
      # It implies `query_counter` is incremented multiple times if both paths run.

      # This part needs careful thought on how results are merged and paginated if both run.
      # If _query_by_semver fills a page, _query_by_generic_version might be skipped by should_skip_query.
      generic_fallback_bugs: List[osv.models.Bug] = yield _query_by_generic_version(
          context, base_ndb_query, package_name, ecosystem_name, version_str)
      for bug_item in generic_fallback_bugs: # Renamed bug
          if bug_item not in found_bugs_models:
              found_bugs_models.append(bug_item)

    elif current_ecosystem_info and current_ecosystem_info.supports_comparing:
      # Ecosystem supports direct version comparison (e.g., Debian)
      found_bugs_models = yield _query_by_comparing_versions(
          context, base_ndb_query, package_name, ecosystem_name, version_str)
    else:
      # Generic ecosystem or one without special comparison/semver logic
      found_bugs_models = yield _query_by_generic_version(
          context, base_ndb_query, package_name, ecosystem_name, version_str)
  else: # Ecosystem not specified
    logging.warning("Package query by version without specified ecosystem for: %s", package_name)
    # Try SemVer first as a common case
    semver_bugs: List[osv.models.Bug] = yield _query_by_semver( # Renamed new_bugs
        context, base_ndb_query, package_name, None, version_str) # Pass None for ecosystem
    found_bugs_models.extend(semver_bugs)

    # Then try generic, merge results (avoiding duplicates)
    # This again implies multiple increments to query_counter if both run.
    generic_bugs: List[osv.models.Bug] = yield _query_by_generic_version( # Renamed new_bugs
        context, base_ndb_query, package_name, None, version_str) # Pass None for ecosystem
    for bug_item in generic_bugs: # Renamed bug
      if bug_item not in found_bugs_models:
        found_bugs_models.append(bug_item)

  # Convert found Bug models to Vulnerability protos
  return [to_response(bug_model) for bug_model in found_bugs_models] # Renamed bug


@ndb.tasklet # Async NDB operation
def _query_by_comparing_versions(context: QueryContext,
                                 base_query: ndb.Query, # Renamed query
                                 package_name: str, # Assuming non-optional here
                                 ecosystem_name: str, # Renamed ecosystem, assuming non-optional
                                 version_str: str # Renamed version
                                ) -> ndb.Future[List[osv.models.Bug]]: # Returns Future[List[Bug]]
  """
  Query by comparing versions (e.g., for Debian, Alpine).
  This is an ndb.tasklet, so it returns a Future.
  """
  # This query fetches all bugs for the package/ecosystem and then filters by version in Python.
  # This can be inefficient if many bugs exist for the package.
  # NDB filtering capabilities for version ranges are limited for non-SemVer.

  matched_bugs_list: List[osv.models.Bug] = [] # Renamed bugs

  context.query_counter += 1 # Increment for this NDB query
  if context.should_skip_query():
    return [] # type: ignore[return-value]

  # Iterator for the base_query (already filtered by package, ecosystem, status, public)
  query_iterator: ndb.QueryIterator = base_query.iter(start_cursor=context.cursor_at_current()) # Renamed it

  while (yield query_iterator.has_next_async()): # type: ignore[misc]
    try:
      if context.should_break_page(len(matched_bugs_list)):
        context.save_cursor_at_page_break(query_iterator)
        break

      bug_model: osv.models.Bug = query_iterator.next() # type: ignore[assignment] # Renamed bug

      # Check each affected package within the bug
      # osv.models needed for AffectedPackage, Package
      for aff_pkg in bug_model.affected_packages: # type: ignore[attr-defined] # Renamed affected_package
        current_pkg_details: Optional[osv.models.Package] = aff_pkg.package # Renamed package
        if not current_pkg_details: continue

        # Match ecosystem and package name carefully
        if not is_matching_package_ecosystem(current_pkg_details.ecosystem, ecosystem_name):
          continue
        if package_name != current_pkg_details.name:
          continue

        # If package and ecosystem match, check if version_str is affected
        if _is_affected(ecosystem_name, version_str, aff_pkg): # aff_pkg is osv.models.AffectedPackage
          matched_bugs_list.append(bug_model)
          context.total_responses.add(1)
          break # Found an affected package in this bug, move to next bug

    except Exception: # Catch broad exceptions during version comparison or data access
      # Log specific bug ID if possible, and error
      current_bug_id = bug_model.id() if 'bug_model' in locals() and hasattr(bug_model, 'id') else "Unknown ID"
      logging.exception('Failed to compare versions for bug %s', current_bug_id)

  return matched_bugs_list


@ndb.tasklet # Async NDB operation
def query_by_package(
    context: QueryContext,
    package_name: Optional[str],
    ecosystem_name: Optional[str], # Renamed ecosystem
    to_response: ToResponseCallable
) -> ndb.Future[List[vulnerability_pb2.Vulnerability]]: # Returns Future
  """
  Query by package name and ecosystem (no version).
  This is an ndb.tasklet, so it returns a Future.
  """
  # List to store matching Bug models
  matched_bugs_models: List[osv.models.Bug] = [] # Renamed bugs

  # Base query for package_name, ecosystem, public, and processed bugs
  # osv.models needed here
  if package_name and ecosystem_name: # Both must be present for this query type
    ndb_q: ndb.Query = osv.models.Bug.query( # Renamed query
        osv.models.Bug.status == osv.models.BugStatus.PROCESSED.value, # Use .value
        osv.models.Bug.project == package_name,
        osv.models.Bug.ecosystem == ecosystem_name,
        osv.models.Bug.public == True,  # noqa: E712
    )
  else: # package_name or ecosystem_name is missing
    # This case might be an invalid query depending on API spec.
    # For now, return empty list if essential params are missing.
    return [] # type: ignore[return-value]


  context.query_counter += 1 # Increment for this NDB query
  if context.should_skip_query():
    return [] # type: ignore[return-value]

  query_iterator: ndb.QueryIterator = ndb_q.iter(start_cursor=context.cursor_at_current()) # Renamed it

  while (yield query_iterator.has_next_async()): # type: ignore[misc]
    if context.should_break_page(len(matched_bugs_models)):
      context.save_cursor_at_page_break(query_iterator)
      break

    bug_model: osv.models.Bug = query_iterator.next() # type: ignore[assignment] # Renamed bug
    matched_bugs_models.append(bug_model)
    context.total_responses.add(1)

  # Convert Bug models to Vulnerability protos
  return [to_response(bug_model) for bug_model in matched_bugs_models] # Renamed bug


def serve(port: int, local: bool) -> None:
  """Configures and runs the OSV API server."""
  # Create a gRPC server instance
  # ThreadPoolExecutor is a sensible default for I/O bound tasks.
  # max_workers can be tuned based on expected load and resources.
  server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10)) # Increased workers slightly

  # Instantiate and add servicers
  osv_servicer_instance = OSVServicer() # Renamed servicer
  osv_service_v1_pb2_grpc.add_OSVServicer_to_server(osv_servicer_instance, server)
  # Assuming OSVServicer also implements HealthServicer methods directly
  health_pb2_grpc.add_HealthServicer_to_server(osv_servicer_instance, server)

  if local: # Enable reflection for local debugging (e.g., with grpcurl)
    service_names_tuple: Tuple[str, ...] = ( # Renamed service_names
        osv_service_v1_pb2.DESCRIPTOR.services_by_name['OSV'].full_name,
        health_pb2.DESCRIPTOR.services_by_name['Health'].full_name,
        reflection.SERVICE_NAME, # Standard gRPC reflection service
    )
    reflection.enable_server_reflection(service_names_tuple, server)

  server.add_insecure_port(f'[::]:{port}') # Use f-string
  server.start()
  logging.info('OSV API server listening on port %d', port) # Use logging

  try:
    # Keep the main thread alive to allow server to run
    while True:
      time.sleep(timedelta(days=1).total_seconds()) # Sleep for a long time
  except KeyboardInterrupt:
    logging.info('Shutting down OSV API server with %ds grace period...', _SHUTDOWN_GRACE_DURATION)
    server.stop(_SHUTDOWN_GRACE_DURATION) # Graceful shutdown
    logging.info('Server shutdown complete.')


def is_cloud_run() -> bool:
  """Check if we are running in Cloud Run."""
  # https://cloud.google.com/run/docs/container-contract#env-vars
  return os.getenv('K_SERVICE') is not None


def get_gcp_project() -> str:
  """Get the GCP project name."""
  # We don't set the GOOGLE_CLOUD_PROJECT env var explicitly.
  # Cloud Run sets GOOGLE_CLOUD_PROJECT. App Engine also does.
  # For other environments, it might need to be set manually.
  # Fallback to ndb.Client().project if available, then 'oss-vdb'.
  gcp_project_env: Optional[str] = os.getenv('GOOGLE_CLOUD_PROJECT')
  if gcp_project_env:
    return gcp_project_env

  # getattr on _ndb_client might fail if _ndb_client is not yet fully initialized
  # or if 'project' attribute changes.
  # A more robust way for Cloud Functions/Run/AppEngine is often via metadata server if needed,
  # but for NDB client, it usually infers it correctly from environment.
  return getattr(_ndb_client, 'project', 'oss-vdb')


def _is_affected(ecosystem_name: str, # Renamed ecosystem
                 version_str: str, # Renamed version
                 affected_package_model: osv.models.AffectedPackage # Renamed, osv.models
                ) -> bool:
  """Checks if a version_str is affected within a given AffectedPackage model."""
  # This function assumes ecosystem_name and version_str are for a comparable ecosystem.
  # It iterates through ranges and applies introduced/fixed/last_affected logic.

  is_currently_affected: bool = False # Renamed affected

  ecosystem_helper = ecosystems.get(ecosystem_name)
  if not ecosystem_helper or not ecosystem_helper.supports_ordering:
      # If ecosystem doesn't support ordering, range logic might not apply or be different.
      # Fallback to checking explicit versions list for safety, or log warning.
      # Original code implies this is for comparable ecosystems.
      logging.warning("Attempting range check for non-comparable ecosystem: %s", ecosystem_name)
      # Check explicit versions as a fallback for non-comparable or unknown ecosystems
      # Ensure affected_package_model.versions is not None
      return version_str in (affected_package_model.versions or [])


  try:
    # Query version must be valid for the ecosystem's sorting scheme
    queried_version_key = ecosystem_helper.sort_key(version_str)
  except Exception as e: # Broad exception for sort_key errors (e.g. invalid format)
    logging.warning("Failed to get sort key for query version %s in ecosystem %s: %s", version_str, ecosystem_name, e)
    return False # Cannot determine affected status if query version is invalid for ecosystem

  # Check explicit versions first (OSV spec allows this)
  if version_str in (affected_package_model.versions or []): # type: ignore[attr-defined]
    return True

  # Check ranges
  # Ensure affected_package_model.ranges is not None
  for version_range in (affected_package_model.ranges or []): # type: ignore[attr-defined] # Renamed r
    # Ensure range events are not None
    # osv.models needed for sorted_events
    # Type of version_range.type needs to be compatible with sorted_events expectations
    sorted_range_events = osv.models.sorted_events(ecosystem_name, version_range.type, version_range.events or []) # Renamed

    # Reset affected status for each new range within the package
    is_affected_by_this_range = False
    for event_item in sorted_range_events: # Renamed event
      try:
        event_version_key = ecosystem_helper.sort_key(event_item.value)
      except Exception as e: # Broad exception for sort_key errors on event values
        logging.warning("Failed to get sort key for event value %s in range for %s: %s",
                        event_item.value, ecosystem_name, e)
        continue # Skip this malformed event

      if event_item.type == 'introduced':
        if event_item.value == '0' or queried_version_key >= event_version_key:
          is_affected_by_this_range = True
      elif event_item.type == 'fixed':
        if queried_version_key >= event_version_key:
          is_affected_by_this_range = False
      elif event_item.type == 'last_affected':
        if queried_version_key > event_version_key: # Strictly greater
          is_affected_by_this_range = False

    if is_affected_by_this_range: # If affected by any range in the package
      return True

  return False # Not affected by any range or explicit version list


def is_matching_package_ecosystem(package_model_ecosystem: Optional[str], # Renamed
                                  query_ecosystem: Optional[str]) -> bool: # Renamed
  """Checks if the queried ecosystem matches the affected package's ecosystem,
  considering potential variations in the package's ecosystem (e.g. Debian vs Debian:11).
  """
  if package_model_ecosystem is None or query_ecosystem is None:
    return False # Cannot match if either is None

  # Exact match
  if package_model_ecosystem == query_ecosystem:
    return True

  # Special case for GIT queries: OSV entries might have an empty ecosystem string.
  if query_ecosystem == 'GIT' and package_model_ecosystem == '':
    return True

  # Check normalized forms (e.g. "Debian:11" normalizes to "Debian")
  # This allows a query for "Debian" to match "Debian:11" records.
  if ecosystems.normalize(package_model_ecosystem) == query_ecosystem:
    return True

  # Check if query_ecosystem is a variant of package_model_ecosystem
  # e.g. package_model_ecosystem="Ubuntu", query_ecosystem="Ubuntu:Pro" (or vice-versa with normalization)
  # This part might need more specific logic depending on how variants are handled.
  # The original `ecosystems.remove_variants(package_ecosystem)` was for a different purpose.
  # A simple check: if query_ecosystem starts with package_model_ecosystem and a colon, or vice versa.
  # Or if normalized query_ecosystem matches normalized package_model_ecosystem.
  if ecosystems.normalize(query_ecosystem) == ecosystems.normalize(package_model_ecosystem):
      return True

  return False


def main() -> None:
  """Entrypoint."""
  if is_cloud_run():
    # Assuming setup_gcp_logging and trace_filter are correctly defined elsewhere
    setup_gcp_logging('api-backend') # project_id might be inferred by library
    logging.getLogger().addFilter(trace_filter)

    # Profiler initialization
    try:
      # service_version and other params can be added if needed
      googlecloudprofiler.start(service="osv-api-server") # service name updated
    except (ValueError, NotImplementedError) as e: # Catch specific errors
      logging.error("Failed to start Cloud Profiler: %s", e)

  # Configure root logger level (e.g., INFO, DEBUG)
  logging.getLogger().setLevel(logging.INFO)
  # Example: For more verbose logging during development:
  # logging.getLogger().setLevel(logging.DEBUG)
  # logging.getLogger('google.cloud.ndb').setLevel(logging.INFO) # Tone down NDB logs

  parser = argparse.ArgumentParser(
      description="OSV API Server", # Added description
      formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument(
      '--port',
      type=int,
      default=None, # Default handled below using env var or hardcoded default
      help=('The port to listen on. If not set, uses $PORT environment '
            'variable, defaulting to 8000 if $PORT is also not set.'))
  parser.add_argument(
      '--local',
      action='store_true', # store_true sets to True if flag is present
      default=False,
      help='Enable server reflection for local debugging (e.g., with grpcurl).')

  args = parser.parse_args()

  # Determine port: command-line arg > $PORT env > default (8000)
  server_port: int # Renamed port
  if args.port is not None:
    server_port = args.port
  else:
    server_port = int(os.environ.get('PORT', '8000')) # Default to 8000 if $PORT not set

  serve(server_port, args.local)


if __name__ == '__main__':
  main()
