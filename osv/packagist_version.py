import re


class PackagistVersion(object):
  """
  Follows the packagist version ordering, which is recommended to be semver, but
  not enforced to be semver. The php standard version comparison code written in
  C is located here: https://github.com/php/php-src/blob/master/ext/standard/versioning.c

  The function first replaces _, - and + with a dot . in the version strings and
  also inserts dots . before and after any non number so that for example
  '4.3.2RC1' becomes '4.3.2.RC.1'. Then it compares the parts starting from
  left to right.

  If a part contains special version strings these are handled in the following order:
  any string not found in this list < dev < alpha = a < beta = b < RC = rc < # < pl = p.
  This way not only versions with different levels like '4.1' and '4.1.2' can be
  compared but also any PHP specific version containing development state.
  """

  version_str: str
  canonicalized_version: str

  def __init__(self, version: str):
    self.version_str = version
    self.canonicalized_version = self.php_canonicalize_version(version)

  def __str__(self) -> str:
    return self.version_str

  def __hash__(self):
    return self.canonicalized_version

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.canonicalized_version == other.canonicalized_version

  def __lt__(self, other):
    return self.__cmp__(other) < 0

  def __le__(self, other):
    return self.__cmp__(other) <= 0

  def __gt__(self, other):
    return self.__cmp__(other) > 0

  def __ge__(self, other):
    return self.__cmp__(other) >= 0

  def __cmp__(self, other):
    return self.php_version_compare(self.version_str, other.version_str)

  @staticmethod
  def php_version_compare(version_a: str, version_b: str) -> int:
    version_a = PackagistVersion.php_canonicalize_version(version_a)
    version_b = PackagistVersion.php_canonicalize_version(version_b)

    a_split = version_a.split('.')
    b_split = version_b.split('.')
    for a, b in zip(a_split, b_split):
      if a.isdigit() and b.isdigit():
        compare = int(a) - int(b)
      elif not a.isdigit() and not b.isdigit():
        compare = PackagistVersion.compare_special_versions(a, b)
      elif a.isdigit():
        compare = PackagistVersion.compare_special_versions('#', b)
      else:
        compare = PackagistVersion.compare_special_versions(a, '#')

      if compare != 0:
        return compare

    if len(a_split) > len(b_split):
      next_char = a_split[len(b_split)]
      if next_char.isdigit():
        return 1
      return PackagistVersion.compare_special_versions(next_char, '#')

    if len(a_split) < len(b_split):
      next_char = b_split[len(a_split)]
      if next_char.isdigit():
        return -1
      return PackagistVersion.compare_special_versions('#', next_char)

    return 0

  @staticmethod
  def php_canonicalize_version(version: str) -> str:
    """
    Replaces special separators (`-`,`_`,`+`) with `.`, and inserts `.`
    between any digit and non-digit.
    """
    replaced = re.sub('[-_+]', '.', version)
    replaced = re.sub(r'([^\d.])(\d)', r'\1.\2', replaced)
    replaced = re.sub(r'(\d)([^\d.])', r'\1.\2', replaced)
    return replaced

  SPECIAL_CHARACTER_ORDER = {
      "dev": 0,
      "alpha": 1,
      "a": 1,
      "beta": 2,
      "b": 2,
      "RC": 3,
      "rc": 3,
      "#": 4,
      "pl": 5,
      "p": 5,
      None: 0,
  }

  @staticmethod
  def compare_special_versions(version_part_a: str, version_part_b: str) -> int:
    """
    Compares the order of special characters against the order specified in php
    docs.

    any string not found in this list < dev < alpha = a < beta = b < RC = rc < # < pl = p.

    :return: 1 if a > b, -1 if b > a, 0 if a == b
    """
    # This isn't quite the behaviour of the c implementation of packagist
    # In packagist if the part starts with special_chars its enough
    found_a = PackagistVersion.SPECIAL_CHARACTER_ORDER.get(version_part_a, -1)
    found_b = PackagistVersion.SPECIAL_CHARACTER_ORDER.get(version_part_b, -1)

    if found_a > found_b:
      return 1
    if found_a < found_b:
      return -1
    return 0
