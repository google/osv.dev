"""opam ecosystem helper."""
import requests

from . import config
from .ecosystems_base import EnumerateError
from .debian import DPKG


# Disable enumerable ecosystem as the record is pre-enumerated on import
class Opam(DPKG):
  """opam packages ecosystem"""

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
          f'Failed to get opam versions for {package} with: {response.text}')

    responses = {}

    if response.status_code == 200:
      responses.extend(response.json())
    if archive_response.status_code == 200:
      responses.extend(archive_response.json())

    versions = [x["name"].removeprefix(package + '.') for x in responses]

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)
