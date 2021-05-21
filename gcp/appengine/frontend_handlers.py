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
"""Handlers for the OSV web frontend."""

import os

from flask import abort
from flask import Blueprint
from flask import jsonify
from flask import render_template
from flask import request

from google.cloud import ndb

import osv
import rate_limiter
import source_mapper

blueprint = Blueprint('frontend_handlers', __name__)

_BACKEND_ROUTE = '/backend'
_PAGE_SIZE = 16
_PAGE_LOOKAHEAD = 4
_IAP_ACCOUNT_NAMESPACE = 'accounts.google.com:'
_OSS_FUZZ_TRACKER_URL = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='
_REQUESTS_PER_MIN = 30


def _is_prod():
  return os.getenv('GAE_ENV', '').startswith('standard')


if _is_prod():
  redis_host = os.environ.get('REDISHOST', 'localhost')
  redis_port = int(os.environ.get('REDISPORT', 6379))
  limiter = rate_limiter.RateLimiter(
      redis_host, redis_port, requests_per_min=_REQUESTS_PER_MIN)

  @blueprint.before_request
  def check_rate_limit():
    ip_addr = request.headers.get('X-Appengine-User-Ip', 'unknown')
    if not limiter.check_request(ip_addr):
      abort(429)


@blueprint.route('/')
def index():
  """Main page."""
  return render_template('index.html')


def _to_commit(bug, commit_hash):
  """Convert a commit hash to a Commit structure."""
  commit = {
      'repoType': 'git',  # TODO(ochang): Remove hardcode.
      'repoUrl': bug.repo_url,
  }

  if ':' in commit_hash:
    commit['type'] = 'range'
    commit['from'], commit['to'] = commit_hash.split(':')
    return commit

  commit['type'] = 'exact'
  commit['commit'] = commit_hash
  return commit


def _get_commits(bug, ranges, attr):
  """Get commits."""
  versions = []
  for i, version in enumerate(set(versions)):
    if version is None:
      continue

    commit = _to_commit(bug, commit_hash)
    commit['link'] = _commit_to_link(commit)
    commit['id'] = i
    commits.append(commit)

  return commits


def bug_to_response(bug, detailed=False):
  """Convert a Bug entity to a response object."""
  response = osv.vulnerability_to_dict(bug.to_vulnerability())
  response.update({
      'isFixed': bug.is_fixed,
      'invalid': bug.status == osv.BugStatus.INVALID
  })

  add_links(response)
  return response


def add_links(bug):
  """Add VCS links where possible."""
  for i, affected in enumerate(bug['affects']['ranges']):
    affected['id'] = i
    if affected['type'] != 'GIT':
      continue

    repo_url = affected.get('repo')
    if not repo_url:
      continue

    if affected.get('introduced'):
      affected['introduced_link'] = _commit_to_link(repo_url, affected['introduced'])

    if affected.get('fixed'):
      affected['fixed_link'] = _commit_to_link(repo_url, affected['fixed'])


def _commit_to_link(repo_url, commit):
  """Convert commit to link."""
  vcs = source_mapper.get_vcs_viewer_for_url(repo_url)
  if not vcs:
    return None

  if ':' not in commit:
    return vcs.get_source_url_for_revision(commit)

  commit_parts = commit.split(':')
  if len(commit_parts) != 2:
    return None

  start, end = commit_parts
  if start == 'unknown':
    return None

  return vcs.get_source_url_for_revision_diff(start, end)


@blueprint.route(_BACKEND_ROUTE + '/query')
def query_handler():
  """Handle a query."""
  search_string = request.args.get('search')
  page = int(request.args.get('page', 1))
  affected_only = request.args.get('affected_only') == 'true'

  query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                        osv.Bug.public == True)  # pylint: disable=singleton-comparison

  if search_string:
    query = query.filter(osv.Bug.search_indices == search_string)

  if affected_only:
    query = query.filter(osv.Bug.has_affected == True)  # pylint: disable=singleton-comparison

  query = query.order(-osv.Bug.sort_key)
  total = query.count()
  results = {
      'total': total,
      'items': [],
  }

  bugs, _, _ = query.fetch_page(
      page_size=_PAGE_SIZE, offset=(page - 1) * _PAGE_SIZE)
  for bug in bugs:
    results['items'].append(bug_to_response(bug))

  return jsonify(results)


@blueprint.route(_BACKEND_ROUTE + '/package')
def package_handler():
  """Handle a package request."""
  package_path = request.args.get('package')
  if not package_path:
    abort(400)
    return None

  parts = package_path.split('/', 1)
  if len(parts) != 2:
    abort(400)
    return None

  ecosystem, package = parts
  package_info = ndb.Key(osv.PackageInfo, package_path).get()
  if package_info and package_info.latest_tag:
    latest_tag = package_info.latest_tag
  else:
    # Fall back to last lexicographically ordered tag.
    latest_tag_info = osv.PackageTagInfo.query(
        osv.PackageTagInfo.package == package,
        osv.PackageTagInfo.ecosystem == ecosystem)
    latest_tag_info = latest_tag_info.order(-osv.PackageTagInfo.tag).get()
    if not latest_tag_info:
      abort(404)
      return None

    latest_tag = latest_tag_info.tag

  query = osv.PackageTagInfo.query(osv.PackageTagInfo.package == package,
                                   osv.PackageTagInfo.ecosystem == ecosystem,
                                   osv.PackageTagInfo.bugs > '')
  tags_with_bugs = []
  for tag_info in query:
    tag_with_bugs = {
        'tag': tag_info.tag,
        'bugs': [osv.Bug.OSV_ID_PREFIX + bug for bug in tag_info.bugs],
    }

    tags_with_bugs.append(tag_with_bugs)

  tags_with_bugs.sort(key=lambda b: b['tag'], reverse=True)
  return jsonify({
      'latestTag': latest_tag,
      'bugs': tags_with_bugs,
  })


@blueprint.route(_BACKEND_ROUTE + '/vulnerability')
def vulnerability_handler():
  """Handle a vulnerability request."""
  vuln_id = request.args.get('id')
  if not vuln_id:
    abort(400)
    return None

  bug = osv.Bug.get_by_id(vuln_id)
  if not bug:
    abort(404)
    return None

  if bug.status == osv.BugStatus.UNPROCESSED:
    abort(404)
    return None

  if not bug.public:
    abort(403)
    return None

  return jsonify(bug_to_response(bug, detailed=True))
