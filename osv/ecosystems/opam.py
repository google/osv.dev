"""OPAM ecosystem helper."""
import requests

from ..third_party.univers.debian import Version as DebianVersion
from . import config
from .ecosystems_base import EnumerableEcosystem, EnumerateError


class Opam(EnumerableEcosystem):
  """OPAM packages ecosystem"""

  def _sort_key(self, version):
    # OPAM uses debian versioning
    if not DebianVersion.is_valid(version):
      # If debian version is not valid, it is most likely an invalid fixed
      # version then sort it to the last/largest element
      return DebianVersion(9999999999, '9999999999')
    return DebianVersion.from_string(version)

  _BASE = 'https://api.github.com/repos/ocaml/'
  _REPO = _BASE + 'opam-repository/contents/packages/'
  _REPO_ARCHIVE = _BASE + 'opam-repository-archive/contents/packages/'

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    response = requests.get(self._REPO + package, timeout=config.timeout)
    archive_response = requests.get(
        self._REPO_ARCHIVE + package, timeout=config.timeout)
    if response.status_code == 404 and archive_response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200 and archive_response.status_code != 200:
      raise RuntimeError(
          f'Failed to get OPAM versions for {package} with: {response.text}')

    responses = {}

    if response.status_code == 200:
      responses.extend(response.json())
    if archive_response.status_code == 200:
      responses.extend(archive_response.json())

    versions = [x["name"].removeprefix(package + '.') for x in responses]

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)
