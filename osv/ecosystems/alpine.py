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
"""Alpine ecosystem helper."""

import glob
import logging
import os.path
import subprocess
import typing

from ..third_party.univers.alpine import AlpineLinuxVersion

from . import config
from .helper_base import Ecosystem, EnumerateError
from .. import repos
from ..cache import cached


class Alpine(Ecosystem):
  """
  Alpine packages ecosystem
  
  Args:
      alpine_release_ver: is used to configure which branch 
      in alpines git repo is used for version enumeration
  """

  # Use github mirror which supports more bandwidth.
  _APORTS_GIT_URL = 'https://github.com/alpinelinux/aports.git'
  _BRANCH_SUFFIX = '-stable'
  alpine_release_ver: str
  _GIT_REPO_PATH = 'version_enum/aports/'
  # Sometimes (2 or 3 packages) APKBUILD files are a bash script and version
  # is actually stored in variables. _kver is the common variable name.
  _PKGVER_ALIASES = ('+pkgver=', '+_kver=')
  _PKGREL_ALIASES = ('+pkgrel=', '+_krel=')

  def __init__(self, alpine_release_ver: str):
    self.alpine_release_ver = alpine_release_ver

  def get_branch_name(self) -> str:
    return self.alpine_release_ver.lstrip('v') + self._BRANCH_SUFFIX

  def sort_key(self, version):
    if not AlpineLinuxVersion.is_valid(version):
      # If version is not valid, it is most likely an invalid input
      # version then sort it to the last/largest element
      return AlpineLinuxVersion('999999')
    return AlpineLinuxVersion(version)

  @staticmethod
  def _process_git_log(output: str) -> list:
    """
    Takes git log diff output,
    finds all changes to pkgver and pkgrel and outputs that in an unsorted list
    """
    all_versions = set()
    # Filter out the relevant lines
    lines = [
        x for x in output.splitlines()
        if len(x) == 0 or x.startswith(Alpine._PKGVER_ALIASES) or
        x.startswith(Alpine._PKGREL_ALIASES)
    ]
    # Reverse so that it's in chronological order.
    # The following loop also expects this order.
    lines.reverse()

    current_ver = None
    current_rel = None

    def clean_versions(ver: str) -> str:
      ver = ver.split(' #')[0]  # Remove comment lines
      ver = ver.strip(' "\'')  # Remove (occasional) quotes
      ver = ver.removeprefix('r')
      return ver

    for line in lines:
      if not line:  # This line ends a commit block
        # Don't add any versions until the entire commit block is finished
        if not current_ver or not current_rel:
          continue

        current_ver = clean_versions(current_ver)
        current_rel = clean_versions(current_rel)
        # Ignore occasional version that is still not valid.
        if AlpineLinuxVersion.is_valid(current_ver) and current_rel.isdigit():
          all_versions.add(current_ver + '-r' + current_rel)
        else:
          logging.warning('Alpine version "%s" - "%s" is not valid',
                          current_ver, current_rel)
        continue

      # Within a commit block, parse all lines and save it till the end
      # of the block
      x_split = line.split('=', 1)
      if len(x_split) != 2:
        # Skip the occasional invalid versions
        continue

      num = x_split[1]
      if line.startswith(Alpine._PKGVER_ALIASES):
        current_ver = num
        continue

      if line.startswith(Alpine._PKGREL_ALIASES):
        current_rel = num
        continue

    # Return unsorted list of versions (as it's converted from a set)
    return list(all_versions)

  def enumerate_versions(self,
                         package: str,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """We use Alpines aports git repository history to do version enum"""

    if config.work_dir is None:
      logging.error(
          "Tried to enumerate alpine version without workdir being set")
      return []

    get_versions = self._get_versions
    if config.shared_cache:
      get_versions = cached(config.shared_cache)(get_versions)

    versions = get_versions(self.get_branch_name(), package)
    self.sort_versions(versions)

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

  @staticmethod
  def _get_versions(branch: str, package: str) -> typing.List[str]:
    """Get all versions for a package from aports repo"""

    # Checkout the repo at the alpine version branch
    checkout_dir = os.path.join(config.work_dir, Alpine._GIT_REPO_PATH)
    repos.ensure_updated_checkout(
        Alpine._APORTS_GIT_URL, checkout_dir, branch=branch)
    directories = glob.glob(
        os.path.join(checkout_dir, '*', package.lower(), 'APKBUILD'),
        recursive=True)

    if len(directories) != 1:
      raise EnumerateError('Cannot find package in aports')

    relative_path = os.path.relpath(directories[0], checkout_dir)

    # Run git log -L to get a list of all changes to the package APKBUILD file
    # Specifically changes to "pkgver=" and "pkgrel="
    regex_test_versions = '\\|'.join(
        ['\\(' + x.removeprefix('+') + '\\)' for x in Alpine._PKGVER_ALIASES])

    regex_test_revisions = '\\|'.join(
        ['\\(' + x.removeprefix('+') + '\\)' for x in Alpine._PKGREL_ALIASES])

    # yapf: disable
    # https://git-scm.com/docs/git-log/2.33.1#Documentation/git-log.txt--Lltstartgtltendgtltfilegt
    stdout_data = subprocess.check_output([
        'git', 'log', '--oneline',
        '-L', '^/' + regex_test_versions  + '/,+1:' + relative_path,
        '-L', '^/' + regex_test_revisions + '/,+1:' + relative_path
    ], cwd=checkout_dir).decode('utf-8')
    # yapf: enable

    versions = Alpine._process_git_log(stdout_data)
    return versions
