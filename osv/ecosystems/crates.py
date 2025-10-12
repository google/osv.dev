"""crates.io ecosystem helper."""

import json
from typing import Final

from . import config
from .ecosystems_base import EnumerableEcosystem, EnumerateError
from .semver_ecosystem_helper import SemverEcosystem
from ..request_helper import RequestError, RequestHelper


class CratesIO(SemverEcosystem, EnumerableEcosystem):
  """Ecosystem helper for crates.io packages."""

  _API_PACKAGE_URL: Final[str] = 'https://crates.io/api/v1/crates/{package}'

  def __init__(self, suffix: str | None = None):
    super().__init__(suffix)
    self._versions_cache: dict[str, list[str]] = {}

  def _fetch_versions(self, package: str) -> list[str]:
    """Fetch the published versions for the given package."""

    normalized = package.lower()
    if normalized in self._versions_cache:
      return self._versions_cache[normalized]

    url = self._API_PACKAGE_URL.format(package=normalized)
    request_helper = RequestHelper(config.shared_cache)

    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError(
          f'Failed to get crates.io versions for {package} with: '
          f'{ex.response.text}') from ex

    payload = json.loads(text_response)
    versions = [
        entry['num'] for entry in payload.get('versions', [])
        if not entry.get('yanked', False)
    ]

    cached_versions = list(versions)
    self.sort_versions(cached_versions)
    self._versions_cache[normalized] = cached_versions
    return cached_versions

  def enumerate_versions(self,
                         package: str,
                         introduced: str | None,
                         fixed: str | None = None,
                         last_affected: str | None = None,
                         limits: list[str] | None = None) -> list[str]:
    versions = self._fetch_versions(package)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

  def resolve_version(self, package: str, version: str) -> str:
    """Enrich a version string with build metadata when available."""

    if not version or '+' in version or version in {'0', '0.0.0-0'}:
      return version

    try:
      versions = self._fetch_versions(package)
    except EnumerateError:
      return version

    if version in versions:
      return version

    prefix = version + '+'
    matches = [candidate for candidate in versions if candidate.startswith(prefix)]

    if len(matches) == 1:
      return matches[0]

    return version
