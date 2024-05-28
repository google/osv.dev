# Copyright 2019 Google LLC
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
"""Helper functions for fetch source links."""
# Based on stripped down version from ClusterFuzz.

import re

RANGE_LIMIT = 10000


class VCSViewer(object):
  """Base viewer class."""
  VCS_URL_REGEX = None
  VCS_REVISION_SUB = None
  VCS_REVISION_DIFF_SUB = None

  def __init__(self, url):
    self.url = url

  def get_mapped_url(self, repl, **kwargs):
    """Return mapped url given a url map and arguments."""
    mapped_url = self.VCS_URL_REGEX.sub(repl, self.url)
    mapped_url = mapped_url.format(**kwargs)
    return mapped_url

  def get_source_url_for_revision(self, revision):
    """Return source revision url given a url and revision."""
    if not self.VCS_REVISION_SUB:
      return None

    return self.get_mapped_url(self.VCS_REVISION_SUB, revision=revision)

  def get_source_url_for_revision_diff(self, start_revision, end_revision):
    """Return source revision diff url given a url and revision."""
    if not self.VCS_REVISION_DIFF_SUB:
      return None

    return self.get_mapped_url(
        self.VCS_REVISION_DIFF_SUB,
        start_revision=start_revision,
        end_revision=end_revision,
        range_limit=RANGE_LIMIT)


class FreeDesktopVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(
      r'https://anongit\.freedesktop\.org/git/(.*)\.git$')
  VCS_REVISION_SUB = r'https://cgit.freedesktop.org/\1/commit/?id={revision}'
  VCS_REVISION_DIFF_SUB = (r'https://cgit.freedesktop.org/\1/diff/'
                           r'?id={end_revision}&id2={start_revision}')


class GitHubVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'(https://github\.com/(.*?))(\.git)?$')
  VCS_REVISION_SUB = r'\1/commit/{revision}'
  VCS_REVISION_DIFF_SUB = r'\1/compare/{start_revision}...{end_revision}'


class GitLabVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(
      r'(https://gitlab(\.[\w\.\-]+)?\.(com|org)/(.*?))(\.git)?$')
  VCS_REVISION_SUB = r'\1/-/commit/{revision}'
  VCS_REVISION_DIFF_SUB = r'\1/-/compare/{start_revision}...{end_revision}'


class GoogleSourceVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(
      r'(https://[^/]+\.googlesource\.com/(.*?))(\.git)?$')
  VCS_REVISION_SUB = r'\1/+/{revision}'
  VCS_REVISION_DIFF_SUB = (
      r'\1/+log/{start_revision}..{end_revision}?pretty=fuller&n={range_limit}')


class MercurialVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'(https?://hg\.(.*))')
  VCS_REVISION_SUB = r'\1/rev/{revision}'
  VCS_REVISION_DIFF_SUB = (r'\1/log?rev={start_revision}%3A%3A{end_revision}'
                           r'&revcount={range_limit}')


class SavannahVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(
      r'(https?://git\.savannah\.(?:non)?gnu\.org)/git/(.*\.git)$')
  VCS_REVISION_SUB = r'\1/cgit/\2/commit?id={revision}'
  VCS_REVISION_DIFF_SUB = (r'\1/cgit/\2/diff/'
                           r'?id={end_revision}&id2={start_revision}')


class FFMpegVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'(https?://git\.ffmpeg\.org)/(.*\.git)$')
  VCS_REVISION_SUB = r'\1/gitweb/\2/commit/{revision}'
  VCS_REVISION_DIFF_SUB = (r'\1/gitweb/\2/commitdiff/'
                           r'{start_revision}..{end_revision}')


class SourcewareVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'git(://sourceware\.org)/git/(.*\.git)$')
  VCS_REVISION_SUB = r'https\1?p=\2;a=commit;h={revision}'
  VCS_REVISION_DIFF_SUB = (r'https\1?p=\2;a=commitdiff;h={start_revision};'
                           r'hp={end_revision}')


class GnuPGVCS(VCSViewer):
  VCS_URL_REGEX = re.compile(r'git(://git\.gnupg\.org)/(.*\.git)$')
  VCS_REVISION_SUB = r'https\1/cgi-bin/gitweb.cgi?p=\2;a=commit;h={revision}'
  VCS_REVISION_DIFF_SUB = (
      r'https\1/cgi-bin/gitweb.cgi?p=\2;a=commitdiff;h={start_revision};'
      r'hp={end_revision}')


VCS_LIST = [
    FreeDesktopVCS,
    GitHubVCS,
    GitLabVCS,
    GoogleSourceVCS,
    MercurialVCS,
    SavannahVCS,
    FFMpegVCS,
    SourcewareVCS,
    GnuPGVCS,
]


def get_vcs_viewer_for_url(url):
  """Return a VCS instance given an input url."""
  for vcs in VCS_LIST:
    if vcs.VCS_URL_REGEX.match(url):
      return vcs(url)

  return None
