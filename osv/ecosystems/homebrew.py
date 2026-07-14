# Copyright 2026 Google LLC
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
"""Homebrew ecosystem helper.

Version comparison ports Homebrew's `PkgVersion` and `Version#<=>`
(https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/version.rb,
https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/pkg_version.rb):
tokenise into numeric / prerelease-marker / patch-marker / string parts and
compare with a two-pointer walk that treats a numeric zero as equal to a
missing token, then break ties on the numeric `_N` revision suffix.
"""

import functools
import re

from .ecosystems_base import OrderedEcosystem, coarse_version_generic

# Token kinds. Negative kinds are prerelease markers (sort below a missing
# token); NUMERIC 0 is equal to a missing token; STRING/PATCH/POST sort above.
_ALPHA, _BETA, _PRE, _RC = -4, -3, -2, -1
_NULL = 0
_STRING, _PATCH, _POST, _NUMERIC = 1, 2, 3, 4

# Matches Homebrew's Version::SCAN_PATTERN. Order matters: prerelease/post
# markers must be tried before the generic numeric/string fallbacks.
_TOKEN_PATTERNS = (
    (_ALPHA, r'alpha[0-9]*|a[0-9]+'),
    (_BETA, r'beta[0-9]*|b[0-9]+'),
    (_PRE, r'pre[0-9]*'),
    (_RC, r'rc[0-9]*'),
    (_PATCH, r'p[0-9]*'),
    (_POST, r'.post[0-9]+'),
    (_NUMERIC, r'[0-9]+'),
    (_STRING, r'[a-z]+'),
)
_SCAN_RE = re.compile('|'.join(f'({p})' for _, p in _TOKEN_PATTERNS), re.I)
_PKG_VERSION_RE = re.compile(r'\A(.+?)(?:_(\d+))?\Z')

_NULL_TOKEN = (_NULL, 0)


def _classify(match: re.Match) -> tuple[int, int | str]:
  """Return (kind, value) for a token regex match."""
  for i, (kind, _) in enumerate(_TOKEN_PATTERNS, start=1):
    text = match.group(i)
    if text is None:
      continue
    if kind == _NUMERIC:
      return (_NUMERIC, int(text))
    if kind == _STRING:
      return (_STRING, text.lower())
    # Composite tokens (alpha/beta/pre/rc/patch/post): compare by the
    # trailing numeric part within the same kind.
    m = re.search(r'[0-9]+', text)
    return (kind, int(m.group(0)) if m else 0)
  raise ValueError('unreachable')


def _tokenise(version: str) -> list[tuple[int, int | str]]:
  return [_classify(m) for m in _SCAN_RE.finditer(version)]


def _cmp_token(a: tuple[int, int | str], b: tuple[int, int | str]) -> int:
  """Port of Homebrew's per-token `<=>` for the same-shape (both numeric,
  both non-numeric, or one side null) case."""
  ak, av = a
  bk, bv = b
  if ak == _NULL:
    if bk == _NULL:
      return 0
    if bk == _NUMERIC:
      return 0 if bv == 0 else -1
    # Prerelease markers sort below release; string/patch/post above.
    return 1 if bk < 0 else -1
  if bk == _NULL:
    return -_cmp_token(b, a)  # pylint: disable=arguments-out-of-order
  if ak == bk:
    return (av > bv) - (av < bv)
  # Cross-kind for non-numeric composites falls through to string comparison
  # in Homebrew (e.g. PatchToken vs PostToken); use kind rank as a total order
  # over the marker kinds, which matches every case Homebrew's spec covers.
  return (ak > bk) - (ak < bk)


def _cmp_version(lt: list, rt: list) -> int:
  """Port of Homebrew's two-pointer `Version#<=>` walk.

  When one side is numeric and the other is not, a positive numeric wins
  outright; a numeric zero is skipped so `2.1.0-p194` and `2.1-p194` align.
  """
  n = max(len(lt), len(rt))
  li = ri = 0
  while li < n:
    a = lt[li] if li < len(lt) else _NULL_TOKEN
    b = rt[ri] if ri < len(rt) else _NULL_TOKEN
    if a == b:
      li += 1
      ri += 1
      continue
    a_num = a[0] == _NUMERIC
    b_num = b[0] == _NUMERIC
    if a_num and not b_num:
      if _cmp_token(a, _NULL_TOKEN) > 0:
        return 1
      li += 1
    elif b_num and not a_num:
      if _cmp_token(b, _NULL_TOKEN) > 0:
        return -1
      ri += 1
    else:
      return _cmp_token(a, b)
  return 0


@functools.total_ordering
class HomebrewPkgVersion:
  """Comparable Homebrew `PkgVersion` (upstream version + `_N` revision)."""

  __slots__ = ('_raw', '_tokens', '_revision')

  def __init__(self, version: str):
    m = _PKG_VERSION_RE.match(version)
    if not m or not m.group(1):
      raise ValueError(f'Invalid version: {version!r}')
    self._raw = version
    self._tokens = _tokenise(m.group(1))
    self._revision = int(m.group(2)) if m.group(2) else 0

  def __repr__(self) -> str:
    return f'HomebrewPkgVersion({self._raw!r})'

  def __eq__(self, other) -> bool:
    if not isinstance(other, HomebrewPkgVersion):
      return NotImplemented
    return (_cmp_version(self._tokens, other._tokens) == 0 and
            self._revision == other._revision)

  def __lt__(self, other) -> bool:
    if not isinstance(other, HomebrewPkgVersion):
      return NotImplemented
    c = _cmp_version(self._tokens, other._tokens)
    if c != 0:
      return c < 0
    return self._revision < other._revision


class Homebrew(OrderedEcosystem):
  """Homebrew ecosystem helper."""

  def _sort_key(self, version):
    return HomebrewPkgVersion(version)

  def coarse_version(self, version: str) -> str:
    """Coarse version.

    Strips any `_N` revision suffix, then treats the version segment as
    dot-separated with implicit digit/non-digit splits, truncating at the
    first non-numeric token so prerelease/patch markers do not violate
    monotonicity (e.g. `1.2.3rc1 < 1.2.3` while both coarse to
    `00:00000001.00000002.00000003`).
    """
    self._sort_key(version)
    m = _PKG_VERSION_RE.match(version)
    return coarse_version_generic(
        m.group(1),
        separators_regex=r'[._\-+~]',
        truncate_regex=None,
        implicit_split=True,
    )
