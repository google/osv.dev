# Copyright 2025 Google LLC
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
"""Upstream computation tests."""
import datetime
import os
import unittest
import logging
from google.cloud import ndb

import osv
import upstream_computation
from osv import tests

TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')


class UpstreamTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Upstream tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name
    tests.reset_emulator()
    osv.Bug(
        id='CVE-1',
        db_id='CVE-1',
        status=1,
        upstream_raw=[],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='CVE-2',
        db_id='CVE-2',
        status=1,
        upstream_raw=['CVE-1'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='CVE-3',
        db_id='CVE-3',
        status=1,
        upstream_raw=['CVE-1', 'CVE-2'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()

    osv.Bug(
        id='CVE-2023-21400',
        db_id='CVE-2023-21400',
        status=1,
        upstream_raw=[],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2025, 1, 14),
    ).put()
    osv.Bug(
        id='UBUNTU-CVE-2023-21400',
        db_id='UBUNTU-CVE-2023-21400',
        status=1,
        upstream_raw=['CVE-2023-21400'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2025, 1, 14),
    ).put()

    osv.Bug(
        id='UBUNTU-CVE-2023-4004',
        db_id='UBUNTU-CVE-2023-4004',
        status=1,
        upstream_raw=['CVE-2023-4004'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2025, 2, 10),
    ).put()

    osv.Bug(
        id='UBUNTU-CVE-2023-4015',
        db_id='UBUNTU-CVE-2023-4015',
        status=1,
        upstream_raw=['CVE-2023-4015'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2025, 2, 10),
    ).put()

    osv.Bug(
        id='USN-6315-1',
        db_id='USN-6315-1',
        status=1,
        upstream_raw=[
            "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400",
            "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776",
            "CVE-2023-3777", "CVE-2023-4004", "CVE-2023-4015",
            "UBUNTU-CVE-2022-40982", "UBUNTU-CVE-2023-20593",
            "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2023-3609",
            "UBUNTU-CVE-2023-3610", "UBUNTU-CVE-2023-3611",
            "UBUNTU-CVE-2023-3776", "UBUNTU-CVE-2023-3777",
            "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 29),
    ).put()

    osv.Bug(
        id='USN-6325-1',
        db_id='USN-6325-1',
        status=1,
        upstream_raw=[
            "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400",
            "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776",
            "CVE-2023-3777", "CVE-2023-4004", "CVE-2023-4015",
            "UBUNTU-CVE-2022-40982", "UBUNTU-CVE-2023-20593",
            "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2023-3609",
            "UBUNTU-CVE-2023-3610", "UBUNTU-CVE-2023-3611",
            "UBUNTU-CVE-2023-3776", "UBUNTU-CVE-2023-3777",
            "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 31),
    ).put()

    osv.Bug(
        id='USN-6330-1',
        db_id='USN-6330-1',
        status=1,
        upstream_raw=[
            "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400",
            "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776",
            "CVE-2023-3777", "CVE-2023-4004", "CVE-2023-4015",
            "UBUNTU-CVE-2022-40982", "UBUNTU-CVE-2023-20593",
            "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2023-3609",
            "UBUNTU-CVE-2023-3610", "UBUNTU-CVE-2023-3611",
            "UBUNTU-CVE-2023-3776", "UBUNTU-CVE-2023-3777",
            "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 31),
    ).put()

    osv.Bug(
        id='USN-6332-1',
        db_id='USN-6332-1',
        status=1,
        upstream_raw=[
            "CVE-2022-40982", "CVE-2022-4269", "CVE-2022-48502",
            "CVE-2023-0597", "CVE-2023-1611", "CVE-2023-1855", "CVE-2023-1990",
            "CVE-2023-2002", "CVE-2023-20593", "CVE-2023-2124",
            "CVE-2023-21400", "CVE-2023-2163", "CVE-2023-2194", "CVE-2023-2235",
            "CVE-2023-2269", "CVE-2023-23004", "CVE-2023-28466",
            "CVE-2023-30772", "CVE-2023-3141", "CVE-2023-32248",
            "CVE-2023-3268", "CVE-2023-33203", "CVE-2023-33288",
            "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35828",
            "CVE-2023-35829", "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611",
            "CVE-2023-3776", "CVE-2023-3777", "CVE-2023-4004", "CVE-2023-4015",
            "UBUNTU-CVE-2022-40982", "UBUNTU-CVE-2022-4269",
            "UBUNTU-CVE-2022-48502", "UBUNTU-CVE-2023-0597",
            "UBUNTU-CVE-2023-1611", "UBUNTU-CVE-2023-1855",
            "UBUNTU-CVE-2023-1990", "UBUNTU-CVE-2023-2002",
            "UBUNTU-CVE-2023-20593", "UBUNTU-CVE-2023-2124",
            "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2023-2163",
            "UBUNTU-CVE-2023-2194", "UBUNTU-CVE-2023-2235",
            "UBUNTU-CVE-2023-2269", "UBUNTU-CVE-2023-23004",
            "UBUNTU-CVE-2023-28466", "UBUNTU-CVE-2023-30772",
            "UBUNTU-CVE-2023-3141", "UBUNTU-CVE-2023-32248",
            "UBUNTU-CVE-2023-3268", "UBUNTU-CVE-2023-33203",
            "UBUNTU-CVE-2023-33288", "UBUNTU-CVE-2023-35823",
            "UBUNTU-CVE-2023-35824", "UBUNTU-CVE-2023-35828",
            "UBUNTU-CVE-2023-35829", "UBUNTU-CVE-2023-3609",
            "UBUNTU-CVE-2023-3610", "UBUNTU-CVE-2023-3611",
            "UBUNTU-CVE-2023-3776", "UBUNTU-CVE-2023-3777",
            "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 31),
    ).put()

    osv.Bug(
        id='USN-6348-1',
        db_id='USN-6348-1',
        status=1,
        upstream_raw=[
            "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400",
            "CVE-2023-3609", "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776",
            "CVE-2023-3777", "CVE-2023-4004", "CVE-2023-4015",
            "UBUNTU-CVE-2022-40982", "UBUNTU-CVE-2023-20593",
            "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2023-3609",
            "UBUNTU-CVE-2023-3610", "UBUNTU-CVE-2023-3611",
            "UBUNTU-CVE-2023-3776", "UBUNTU-CVE-2023-3777",
            "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 9, 6),
    ).put()

    osv.Bug(
        id='USN-7234-1',
        db_id='USN-7234-1',
        status=1,
        upstream_raw=[
            "CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103",
            "CVE-2024-53141", "CVE-2024-53164", "UBUNTU-CVE-2023-21400",
            "UBUNTU-CVE-2024-40967", "UBUNTU-CVE-2024-53103",
            "UBUNTU-CVE-2024-53141", "UBUNTU-CVE-2024-53164"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 31),
    ).put()

    osv.Bug(
        id='USN-7234-3',
        db_id='USN-7234-3',
        status=1,
        upstream_raw=[
            "CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103",
            "CVE-2024-53141", "CVE-2024-53164", "UBUNTU-CVE-2023-21400",
            "UBUNTU-CVE-2024-40967", "UBUNTU-CVE-2024-53103",
            "UBUNTU-CVE-2024-53141", "UBUNTU-CVE-2024-53164"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2025, 2, 4),
    ).put()

    osv.Bug(
        id='USN-7234-2',
        db_id='USN-7234-2',
        status=1,
        upstream_raw=[
            "CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103",
            "CVE-2024-53141", "CVE-2024-53164", "UBUNTU-CVE-2023-21400",
            "UBUNTU-CVE-2024-40967", "UBUNTU-CVE-2024-53103",
            "UBUNTU-CVE-2024-53141", "UBUNTU-CVE-2024-53164"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 31),
    ).put()

    osv.Bug(
        id='DLA-3623-1',
        db_id='DLA-3623-1',
        status=1,
        upstream_raw=[
            "CVE-2022-39189", "CVE-2022-4269", "CVE-2023-1206", "CVE-2023-1380",
            "CVE-2023-2002", "CVE-2023-2007", "CVE-2023-20588", "CVE-2023-2124",
            "CVE-2023-21255", "CVE-2023-21400", "CVE-2023-2269",
            "CVE-2023-2898", "CVE-2023-3090", "CVE-2023-31084", "CVE-2023-3111",
            "CVE-2023-3141", "CVE-2023-3212", "CVE-2023-3268", "CVE-2023-3338",
            "CVE-2023-3389", "CVE-2023-34256", "CVE-2023-34319",
            "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35824",
            "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3772", "CVE-2023-3773",
            "CVE-2023-3776", "CVE-2023-3863", "CVE-2023-4004", "CVE-2023-40283",
            "CVE-2023-4132", "CVE-2023-4147", "CVE-2023-4194", "CVE-2023-4244",
            "CVE-2023-4273", "CVE-2023-42753", "CVE-2023-42755",
            "CVE-2023-42756", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4921"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2024, 1, 9),
    ).put()

    osv.Bug(
        id='SUSE-SU-2023:3313-1',
        db_id='SUSE-SU-2023:3313-1',
        status=1,
        upstream_raw=[
            "CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569",
            "CVE-2023-21400", "CVE-2023-2156", "CVE-2023-2166",
            "CVE-2023-31083", "CVE-2023-3268", "CVE-2023-3567", "CVE-2023-3609",
            "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-4004"
        ],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 14),
    ).put()

  def test_compute_upstream_basic(self):
    """Tests basic case.
    CVE-1-> CVE-2 -> CVE-3
    Upstream of CVE-3 is CVE-2 & CVE-1
    """

    bugs_query = osv.Bug.query(
        ndb.OR(osv.Bug.upstream_raw > '', osv.Bug.upstream_raw < ''))

    bugs = {bug.db_id: bug for bug in bugs_query.iter()}
    bug_ids = upstream_computation.compute_upstream(bugs.get('CVE-3'), bugs)
    self.assertEqual(['CVE-1', 'CVE-2'], bug_ids)

  def test_compute_upstream_example(self):
    """Test real world case with multiple levels"""

    bugs_query = osv.Bug.query(
        ndb.OR(osv.Bug.upstream_raw > '', osv.Bug.upstream_raw < ''))

    bugs = {bug.db_id: bug for bug in bugs_query.iter()}
    bug_ids = upstream_computation.compute_upstream(
        bugs.get('USN-7234-3'), bugs)
    self.assertEqual([
        "CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103", "CVE-2024-53141",
        "CVE-2024-53164", "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2024-40967",
        "UBUNTU-CVE-2024-53103", "UBUNTU-CVE-2024-53141",
        "UBUNTU-CVE-2024-53164"
    ], bug_ids)

  def test_incomplete_compute_upstream(self):
    """ Test when incomplete upstream information is given 
         VULN-1 -> VULN-2, VULN-3 -> VULN-4
    """
    osv.Bug(
        id='VULN-1',
        db_id='VULN-1',
        status=1,
        upstream_raw=[],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 14),
    ).put()
    osv.Bug(
        id='VULN-2',
        db_id='VULN-2',
        status=1,
        upstream_raw=['VULN-1'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 14),
    ).put()
    osv.Bug(
        id='VULN-3',
        db_id='VULN-3',
        status=1,
        upstream_raw=['VULN-1'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 14),
    ).put()
    osv.Bug(
        id='VULN-4',
        db_id='VULN-4',
        status=1,
        upstream_raw=['VULN-3'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 8, 14),
    ).put()
    bugs_query = osv.Bug.query(
        ndb.OR(osv.Bug.upstream_raw > '', osv.Bug.upstream_raw < ''))
    bugs = {bug.db_id: bug for bug in bugs_query.iter()}
    bug_ids = upstream_computation.compute_upstream(bugs.get('VULN-4'), bugs)
    self.assertEqual(['VULN-1', 'VULN-3'], bug_ids)

  def test_upstream_group_basic(self):
    """Test the upstream group get by db_id"""
    upstream_computation.main()
    osv.UpstreamGroup(
        db_id='CVE-3',
        upstream_ids=['CVE-1', 'CVE-2'],
        last_modified=datetime.datetime(2024, 1, 1),
    ).put()
    bug_ids = osv.UpstreamGroup.query(
        osv.UpstreamGroup.db_id == 'CVE-3').get().upstream_ids
    self.assertEqual(['CVE-1', 'CVE-2'], bug_ids)

  def test_upstream_group_empty(self):
    upstream_computation.main()
    bug_ids = osv.UpstreamGroup.query(
        osv.UpstreamGroup.db_id == 'CVE-1').get().upstream_ids
    self.assertEqual([], bug_ids)

  def test_upstream_group_complex(self):
    """Testing more complex, realworld case"""
    upstream_ids = [
        "CVE-2023-21400", "CVE-2024-40967", "CVE-2024-53103", "CVE-2024-53141",
        "CVE-2024-53164", "UBUNTU-CVE-2023-21400", "UBUNTU-CVE-2024-40967",
        "UBUNTU-CVE-2024-53103", "UBUNTU-CVE-2024-53141",
        "UBUNTU-CVE-2024-53164"
    ]

    upstream_computation.main()
    bug_ids = osv.UpstreamGroup.query(
        osv.UpstreamGroup.db_id == 'USN-7234-3').get().upstream_ids

    self.assertEqual(upstream_ids, bug_ids)


if __name__ == '__main__':
  ds_emulator = tests.start_datastore_emulator()
  try:
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      logging.getLogger("UpstreamTest.test_compute_upstream").setLevel(
          logging.DEBUG)
      unittest.main()
  finally:
    tests.stop_emulator()
