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


def _get_commits(bug, commit_hashes):
  """Get commits."""
  commits = []
  for i, commit_hash in enumerate(set(commit_hashes)):
    if commit_hash is None:
      continue

    commit = _to_commit(bug, commit_hash)
    commit['link'] = _commit_to_link(commit)
    commit['id'] = i
    commits.append(commit)

  return commits


def _get_affected(bug):
  """Get affected tags."""
  result = []
  for affected in bug.affected:
    result.append({
        'tag': affected,
    })

  return result


def bug_to_response(bug, detailed=False):
  """Convert a Bug entity to a response object."""
  response = {
      'id': bug.key.id(),
      'summary': bug.summary,
      'package': {
          'name': bug.project,
          'ecosystem': bug.ecosystem,
      },
      'isFixed': bool(bug.fixed),
      'invalid': bug.status == osv.BugStatus.INVALID
  }

  if bug.status == osv.BugStatus.INVALID:
    response['affected'] = []
  else:
    response['affected'] = _get_affected(bug)

  if detailed:
    response['repo_url'] = bug.repo_url
    response['details'] = bug.details
    response['severity'] = bug.severity
    response['references'] = bug.reference_urls
    response['regressed'] = _get_commits(bug, [bug.regressed] + [
        commit_range.introduced_in
        for commit_range in bug.additional_commit_ranges
    ])

    if bug.fixed:
      response['fixed'] = _get_commits(bug, [bug.fixed] + [
          commit_range.fixed_in for commit_range in bug.additional_commit_ranges
      ])

    if bug.status == osv.BugStatus.INVALID:
      response['regressed'] = [_to_commit(bug, 'INVALID')]
      response['fixed'] = [_to_commit(bug, 'INVALID')]
      response['details'] = 'INVALID'
      response['severity'] = 'INVALID'

  return response


def _commit_to_link(commit):
  """Convert commit to link."""
  vcs = source_mapper.get_vcs_viewer_for_url(commit['repoUrl'])
  if not vcs:
    return None

  if commit['type'] == 'exact':
    return vcs.get_source_url_for_revision(commit['commit'])

  if commit['from'] == 'unknown':
    return None

  return vcs.get_source_url_for_revision_diff(commit['from'], commit['to'])


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
  results = {
      'total': (page + _PAGE_LOOKAHEAD) * _PAGE_SIZE,
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

  ecosystem, package = package_path.split('/', 1)

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
        'bugs': tag_info.bugs,
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

  bug = ndb.Key(osv.Bug, vuln_id).get()
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
