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
"""Bug helper tests."""

import unittest

from . import purl_helpers


class PurlHelpersTest(unittest.TestCase):
  """purl_helpers tests."""

  def tests_package_to_purl(self):
    """Test PURL generation."""
    self.assertEqual('pkg:rpm/almalinux/libvpx',
                     purl_helpers.package_to_purl('AlmaLinux', 'libvpx'))

    self.assertEqual('pkg:apk/alpine/postgresql14?arch=source',
                     purl_helpers.package_to_purl('Alpine', 'postgresql14'))

    self.assertEqual('pkg:apk/chainguard/solr',
                     purl_helpers.package_to_purl('Chainguard', 'solr'))

    self.assertEqual('pkg:cran/commonmark',
                     purl_helpers.package_to_purl('CRAN', 'commonmark'))

    self.assertEqual('pkg:conan/openssl',
                     purl_helpers.package_to_purl('ConanCenter', 'openssl'))

    self.assertEqual('pkg:pypi/django',
                     purl_helpers.package_to_purl('PyPI', 'django'))

    self.assertEqual('pkg:rpm/mageia/python-aiohttp',
                     purl_helpers.package_to_purl('Mageia', 'python-aiohttp'))

    self.assertEqual(
        'pkg:maven/org.apache.struts/struts2-core',
        purl_helpers.package_to_purl('Maven', 'org.apache.struts:struts2-core'))

    self.assertEqual('pkg:apk/minimos/nginx',
                     purl_helpers.package_to_purl('MinimOS', 'nginx'))

    self.assertEqual('pkg:npm/%40hapi/hoek',
                     purl_helpers.package_to_purl('npm', '@hapi/hoek'))

    self.assertEqual('pkg:deb/debian/nginx?arch=source',
                     purl_helpers.package_to_purl('Debian', 'nginx'))

    self.assertEqual('pkg:apk/alpine/nginx?arch=source',
                     purl_helpers.package_to_purl('Alpine', 'nginx'))

    self.assertEqual('pkg:pub/characters',
                     purl_helpers.package_to_purl('Pub', 'characters'))

    self.assertEqual(
        'pkg:swift/github.com/Alamofire/Alamofire',
        purl_helpers.package_to_purl('SwiftURL',
                                     'github.com/Alamofire/Alamofire'))

    # Reverted tests based on test_parse_purl (without parse_purl calls)
    self.assertEqual('pkg:bitnami/moodl',
                     purl_helpers.package_to_purl('Bitnami', 'moodl'))

    self.assertEqual('pkg:cargo/surrealdb',
                     purl_helpers.package_to_purl('crates.io', 'surrealdb'))

    self.assertEqual(
        'pkg:golang/github.com/treeverse/lakefs',
        purl_helpers.package_to_purl('Go', 'github.com/treeverse/lakefs'))

    self.assertEqual('pkg:hackage/process',
                     purl_helpers.package_to_purl('Hackage', 'process'))

    self.assertEqual('pkg:hex/test-package',
                     purl_helpers.package_to_purl('Hex', 'test-package'))

    self.assertEqual('pkg:hex/acme/foo',
                     purl_helpers.package_to_purl('Hex', 'acme/foo'))

    self.assertEqual('pkg:npm/test-package',
                     purl_helpers.package_to_purl('npm', 'test-package'))

    self.assertEqual('pkg:nuget/test-package',
                     purl_helpers.package_to_purl('NuGet', 'test-package'))

    self.assertEqual('pkg:rpm/opensuse/test-package',
                     purl_helpers.package_to_purl('openSUSE', 'test-package'))

    self.assertEqual('pkg:generic/test-package',
                     purl_helpers.package_to_purl('OSS-Fuzz', 'test-package'))

    self.assertEqual(
        'pkg:composer/spencer14420/sp-php-email-handler',
        purl_helpers.package_to_purl('Packagist',
                                     'spencer14420/sp-php-email-handler'))

    self.assertEqual('pkg:pub/test-package',
                     purl_helpers.package_to_purl('Pub', 'test-package'))

    self.assertEqual('pkg:rpm/redhat/test-package',
                     purl_helpers.package_to_purl('Red Hat', 'test-package'))

    self.assertEqual(
        'pkg:rpm/rocky-linux/test-package',
        purl_helpers.package_to_purl('Rocky Linux', 'test-package'))

    self.assertEqual('pkg:gem/test-package',
                     purl_helpers.package_to_purl('RubyGems', 'test-package'))

    self.assertEqual('pkg:rpm/suse/test-package',
                     purl_helpers.package_to_purl('SUSE', 'test-package'))

    self.assertEqual(
        'pkg:swift/github.com/shareup/wasm-interpreter-apple',
        purl_helpers.package_to_purl(
            'SwiftURL', 'github.com/shareup/wasm-interpreter-apple'))

    self.assertEqual('pkg:deb/ubuntu/pygments',
                     purl_helpers.package_to_purl('Ubuntu', 'pygments'))

    self.assertEqual('pkg:apk/wolfi/test-package',
                     purl_helpers.package_to_purl('Wolfi', 'test-package'))

    self.assertIsNone(purl_helpers.package_to_purl('Invalid', 'test-package'))

  def test_parse_purl(self):
    """Test parse purl"""
    self.assertEqual(('AlmaLinux', 'libvpx', None),
                     purl_helpers.parse_purl('pkg:rpm/almalinux/libvpx'))

    self.assertEqual(
        ('Alpine', 'postgresql14', None),
        purl_helpers.parse_purl('pkg:apk/alpine/postgresql14?arch=source'))

    self.assertEqual(('Bitnami', 'moodl', None),
                     purl_helpers.parse_purl('pkg:bitnami/moodl'))

    self.assertEqual(('Chainguard', 'solr', None),
                     purl_helpers.parse_purl('pkg:apk/chainguard/solr'))

    self.assertEqual(('crates.io', 'surrealdb', '2.1.0'),
                     purl_helpers.parse_purl('pkg:cargo/surrealdb@2.1.0'))

    self.assertEqual(('CRAN', 'commonmark', None),
                     purl_helpers.parse_purl('pkg:cran/commonmark'))

    self.assertEqual(('ConanCenter', 'openssl', '3.0.3'),
                     purl_helpers.parse_purl('pkg:conan/openssl@3.0.3'))

    self.assertEqual(('Debian', 'mpg123', '1.26.4-1+deb11u1'),
                     purl_helpers.parse_purl(
                         'pkg:deb/debian/mpg123@1.26.4-1+deb11u1?arch=source'))

    self.assertEqual(('Go', 'github.com/treeverse/lakefs', '1.33.0'),
                     purl_helpers.parse_purl(
                         'pkg:golang/github.com/treeverse/lakefs@1.33.0'))

    self.assertEqual(
        ('Go', 'github.com/jackc/pgx/v5', 'v5.6.0'),
        purl_helpers.parse_purl('pkg:golang/github.com/jackc/pgx@v5.6.0#v5'))

    self.assertEqual(('Hackage', 'process', None),
                     purl_helpers.parse_purl('pkg:hackage/process'))

    self.assertEqual(('Hex', 'test-package', None),
                     purl_helpers.parse_purl('pkg:hex/test-package'))

    self.assertEqual(('Hex', 'acme/foo', '2.3.'),
                     purl_helpers.parse_purl('pkg:hex/acme/foo@2.3.'))

    self.assertEqual(('Mageia', 'python-aiohttp', None),
                     purl_helpers.parse_purl(
                         'pkg:rpm/mageia/python-aiohttp?distro=mageia-9'))

    self.assertEqual(('Maven', 'org.apache.struts:struts2-core', '1.0.0'),
                     purl_helpers.parse_purl(
                         'pkg:maven/org.apache.struts/struts2-core@1.0.0'))

    self.assertEqual(('MinimOS', 'nginx', None),
                     purl_helpers.parse_purl('pkg:apk/minimos/nginx'))

    self.assertEqual(('npm', '@hapi/hoek', '1.2.3'),
                     purl_helpers.parse_purl('pkg:npm/%40hapi/hoek@1.2.3'))

    self.assertEqual(('npm', 'test-package', None),
                     purl_helpers.parse_purl('pkg:npm/test-package'))

    self.assertEqual(('NuGet', 'test-package', '1.2.3'),
                     purl_helpers.parse_purl('pkg:nuget/test-package@1.2.3'))

    self.assertEqual(
        ('openSUSE', 'test-package', '1.2.3'),
        purl_helpers.parse_purl('pkg:rpm/opensuse/test-package@1.2.3'))

    self.assertEqual(('OSS-Fuzz', 'test-package', None),
                     purl_helpers.parse_purl('pkg:generic/test-package'))

    self.assertEqual(
        ('Packagist', 'spencer14420/sp-php-email-handler', '1.2.3'),
        purl_helpers.parse_purl(
            'pkg:composer/spencer14420/sp-php-email-handler@1.2.3'))

    self.assertEqual(('Pub', 'test-package', '1.2.3'),
                     purl_helpers.parse_purl('pkg:pub/test-package@1.2.3'))

    self.assertEqual(('PyPI', 'test-package', '1.2.3'),
                     purl_helpers.parse_purl('pkg:pypi/test-package@1.2.3'))

    self.assertEqual(
        ('Red Hat', 'test-package', '1.2.3'),
        purl_helpers.parse_purl('pkg:rpm/redhat/test-package@1.2.3'))

    self.assertEqual(
        ('Rocky Linux', 'test-package', '1.2.3'),
        purl_helpers.parse_purl('pkg:rpm/rocky-linux/test-package@1.2.3'))

    self.assertEqual(('RubyGems', 'test-package', '1.2.3'),
                     purl_helpers.parse_purl('pkg:gem/test-package@1.2.3'))

    self.assertEqual(('SUSE', 'test-package', '1.2.3'),
                     purl_helpers.parse_purl('pkg:rpm/suse/test-package@1.2.3'))

    self.assertEqual(
        ('SwiftURL', 'github.com/shareup/wasm-interpreter-apple', None),
        purl_helpers.parse_purl(
            'pkg:swift/github.com/shareup/wasm-interpreter-apple'))

    self.assertEqual(('Ubuntu', 'pygments', '2.11.2+dfsg-2ubuntu0.1'),
                     purl_helpers.parse_purl(
                         'pkg:deb/ubuntu/pygments@2.11.2+dfsg-2ubuntu0.1'))

    self.assertEqual(
        ('Wolfi', 'test-package', '1.2.3'),
        purl_helpers.parse_purl('pkg:apk/wolfi/test-package@1.2.3'))

    self.assertIsNone(purl_helpers.parse_purl('pkg:bad/ubuntu/pygments'))

    with self.assertRaises(ValueError):
      purl_helpers.parse_purl('purl:apk/wolfi/test-package@1.2.3')

    self.assertEqual(
        'Alpine',
        purl_helpers.parse_purl('pkg:apk/alpine/postgresql14').ecosystem)

    self.assertEqual('moodl',
                     purl_helpers.parse_purl('pkg:bitnami/moodl').package)

    self.assertEqual(
        '2.11.2',
        purl_helpers.parse_purl('pkg:deb/ubuntu/pygments@2.11.2').version)


if __name__ == '__main__':
  unittest.main()
