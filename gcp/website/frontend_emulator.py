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
"""Frontend emulator to mock local data instead of from GCP"""
from osv import tests
from google.cloud import ndb
import osv
import datetime


def setUp():
  """ Set Up a series of bugs and UpstreamGroups to put in the emulator
  for testing purposes."""
  tests.reset_emulator()
  osv.Bug(
      id='CVE-1',
      db_id='CVE-1',
      status=1,
      upstream_raw=[],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 1, 1),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()
  osv.Bug(
      id='CVE-2',
      db_id='CVE-2',
      status=1,
      upstream_raw=['CVE-1'],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 1, 1),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()
  osv.Bug(
      id='CVE-3',
      db_id='CVE-3',
      status=1,
      upstream_raw=['CVE-1', 'CVE-2'],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 1, 1),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='CVE-2023-21400',
      db_id='CVE-2023-21400',
      status=1,
      upstream_raw=[],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2025, 1, 14),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()
  osv.Bug(
      id='UBUNTU-CVE-2023-21400',
      db_id='UBUNTU-CVE-2023-21400',
      status=1,
      upstream_raw=['CVE-2023-21400'],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2025, 1, 14),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='UBUNTU-CVE-2023-4004',
      db_id='UBUNTU-CVE-2023-4004',
      status=1,
      upstream_raw=['CVE-2023-4004'],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2025, 2, 10),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='UBUNTU-CVE-2023-4015',
      db_id='UBUNTU-CVE-2023-4015',
      status=1,
      upstream_raw=['CVE-2023-4015'],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2025, 2, 10),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='USN-6315-1',
      db_id='USN-6315-1',
      status=1,
      upstream_raw=[
          "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400", "CVE-2023-3609",
          "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777",
          "CVE-2023-4004", "CVE-2023-4015", "UBUNTU-CVE-2022-40982",
          "UBUNTU-CVE-2023-20593", "UBUNTU-CVE-2023-21400",
          "UBUNTU-CVE-2023-3609", "UBUNTU-CVE-2023-3610",
          "UBUNTU-CVE-2023-3611", "UBUNTU-CVE-2023-3776",
          "UBUNTU-CVE-2023-3777", "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 8, 29),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='USN-6325-1',
      db_id='USN-6325-1',
      status=1,
      upstream_raw=[
          "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400", "CVE-2023-3609",
          "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777",
          "CVE-2023-4004", "CVE-2023-4015", "UBUNTU-CVE-2022-40982",
          "UBUNTU-CVE-2023-20593", "UBUNTU-CVE-2023-21400",
          "UBUNTU-CVE-2023-3609", "UBUNTU-CVE-2023-3610",
          "UBUNTU-CVE-2023-3611", "UBUNTU-CVE-2023-3776",
          "UBUNTU-CVE-2023-3777", "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 8, 31),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='USN-6330-1',
      db_id='USN-6330-1',
      status=1,
      upstream_raw=[
          "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400", "CVE-2023-3609",
          "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777",
          "CVE-2023-4004", "CVE-2023-4015", "UBUNTU-CVE-2022-40982",
          "UBUNTU-CVE-2023-20593", "UBUNTU-CVE-2023-21400",
          "UBUNTU-CVE-2023-3609", "UBUNTU-CVE-2023-3610",
          "UBUNTU-CVE-2023-3611", "UBUNTU-CVE-2023-3776",
          "UBUNTU-CVE-2023-3777", "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 8, 31),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='USN-6332-1',
      db_id='USN-6332-1',
      status=1,
      upstream_raw=[
          "CVE-2022-40982", "CVE-2022-4269", "CVE-2022-48502", "CVE-2023-0597",
          "CVE-2023-1611", "CVE-2023-1855", "CVE-2023-1990", "CVE-2023-2002",
          "CVE-2023-20593", "CVE-2023-2124", "CVE-2023-21400", "CVE-2023-2163",
          "CVE-2023-2194", "CVE-2023-2235", "CVE-2023-2269", "CVE-2023-23004",
          "CVE-2023-28466", "CVE-2023-30772", "CVE-2023-3141", "CVE-2023-32248",
          "CVE-2023-3268", "CVE-2023-33203", "CVE-2023-33288", "CVE-2023-35823",
          "CVE-2023-35824", "CVE-2023-35828", "CVE-2023-35829", "CVE-2023-3609",
          "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777",
          "CVE-2023-4004", "CVE-2023-4015", "UBUNTU-CVE-2022-40982",
          "UBUNTU-CVE-2022-4269", "UBUNTU-CVE-2022-48502",
          "UBUNTU-CVE-2023-0597", "UBUNTU-CVE-2023-1611",
          "UBUNTU-CVE-2023-1855", "UBUNTU-CVE-2023-1990",
          "UBUNTU-CVE-2023-2002", "UBUNTU-CVE-2023-20593",
          "UBUNTU-CVE-2023-2124", "UBUNTU-CVE-2023-21400",
          "UBUNTU-CVE-2023-2163", "UBUNTU-CVE-2023-2194",
          "UBUNTU-CVE-2023-2235", "UBUNTU-CVE-2023-2269",
          "UBUNTU-CVE-2023-23004", "UBUNTU-CVE-2023-28466",
          "UBUNTU-CVE-2023-30772", "UBUNTU-CVE-2023-3141",
          "UBUNTU-CVE-2023-32248", "UBUNTU-CVE-2023-3268",
          "UBUNTU-CVE-2023-33203", "UBUNTU-CVE-2023-33288",
          "UBUNTU-CVE-2023-35823", "UBUNTU-CVE-2023-35824",
          "UBUNTU-CVE-2023-35828", "UBUNTU-CVE-2023-35829",
          "UBUNTU-CVE-2023-3609", "UBUNTU-CVE-2023-3610",
          "UBUNTU-CVE-2023-3611", "UBUNTU-CVE-2023-3776",
          "UBUNTU-CVE-2023-3777", "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 8, 31),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='USN-6348-1',
      db_id='USN-6348-1',
      status=1,
      upstream_raw=[
          "CVE-2022-40982", "CVE-2023-20593", "CVE-2023-21400", "CVE-2023-3609",
          "CVE-2023-3610", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3777",
          "CVE-2023-4004", "CVE-2023-4015", "UBUNTU-CVE-2022-40982",
          "UBUNTU-CVE-2023-20593", "UBUNTU-CVE-2023-21400",
          "UBUNTU-CVE-2023-3609", "UBUNTU-CVE-2023-3610",
          "UBUNTU-CVE-2023-3611", "UBUNTU-CVE-2023-3776",
          "UBUNTU-CVE-2023-3777", "UBUNTU-CVE-2023-4004", "UBUNTU-CVE-2023-4015"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 9, 6),
      timestamp=datetime.datetime(2023, 8, 14),
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
      timestamp=datetime.datetime(2023, 8, 14),
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
      timestamp=datetime.datetime(2023, 8, 14),
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
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='DLA-3623-1',
      db_id='DLA-3623-1',
      status=1,
      upstream_raw=[
          "CVE-2022-39189", "CVE-2022-4269", "CVE-2023-1206", "CVE-2023-1380",
          "CVE-2023-2002", "CVE-2023-2007", "CVE-2023-20588", "CVE-2023-2124",
          "CVE-2023-21255", "CVE-2023-21400", "CVE-2023-2269", "CVE-2023-2898",
          "CVE-2023-3090", "CVE-2023-31084", "CVE-2023-3111", "CVE-2023-3141",
          "CVE-2023-3212", "CVE-2023-3268", "CVE-2023-3338", "CVE-2023-3389",
          "CVE-2023-34256", "CVE-2023-34319", "CVE-2023-35788",
          "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-3609", "CVE-2023-3611",
          "CVE-2023-3772", "CVE-2023-3773", "CVE-2023-3776", "CVE-2023-3863",
          "CVE-2023-4004", "CVE-2023-40283", "CVE-2023-4132", "CVE-2023-4147",
          "CVE-2023-4194", "CVE-2023-4244", "CVE-2023-4273", "CVE-2023-42753",
          "CVE-2023-42755", "CVE-2023-42756", "CVE-2023-4622", "CVE-2023-4623",
          "CVE-2023-4921"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2024, 1, 9),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id='SUSE-SU-2023:3313-1',
      db_id='SUSE-SU-2023:3313-1',
      status=1,
      upstream_raw=[
          "CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-21400",
          "CVE-2023-2156", "CVE-2023-2166", "CVE-2023-31083", "CVE-2023-3268",
          "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776",
          "CVE-2023-4004"
      ],
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 8, 14),
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.UpstreamGroup(
      id='SUSE-SU-2023:3313-1',
      db_id='SUSE-SU-2023:3313-1',
      upstream_ids=[
          "CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-21400",
          "CVE-2023-2156", "CVE-2023-2166", "CVE-2023-31083", "CVE-2023-3268",
          "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776",
          "CVE-2023-4004"
      ],
      last_modified=datetime.datetime(2023, 8, 14)).put()

  osv.Bug(
      id="CVE-2021-44228",
      db_id="CVE-2021-44228",
      public=True,
      last_modified=datetime.datetime(2025, 2, 4),
      source="test",
      timestamp=datetime.datetime(2023, 8, 14),
  ).put()

  osv.Bug(
      id="CYCLE-ROOT-1",
      db_id="CYCLE-ROOT-1",
      upstream_raw=['CYCLE-ROOT-2'],
      public=True,
      last_modified=datetime.datetime(2025, 2, 4),
      source="test",
      timestamp=datetime.datetime(2023, 8, 14)).put()
  osv.Bug(
      id="CYCLE-ROOT-2",
      db_id="CYCLE-ROOT-2",
      upstream_raw=['CYCLE-ROOT-1'],
      public=True,
      last_modified=datetime.datetime(2025, 2, 4),
      source="test",
      timestamp=datetime.datetime(2023, 8, 14)).put()
  osv.Bug(
      id="CYCLE-ROOT-3",
      db_id="CYCLE-ROOT-3",
      upstream_raw=['CYCLE-ROOT-1', 'CYCLE-ROOT-2'],
      public=True,
      last_modified=datetime.datetime(2025, 2, 4),
      source="test",
      timestamp=datetime.datetime(2023, 8, 14)).put()

  osv.UpstreamGroup(
      id='CYCLE-ROOT-3',
      db_id='CYCLE-ROOT-3',
      upstream_ids=['CYCLE-ROOT-1', 'CYCLE-ROOT-2'],
      last_modified=datetime.datetime(2023, 8, 14)).put()
  osv.UpstreamGroup(
      id='CYCLE-ROOT-1',
      db_id='CYCLE-ROOT-1',
      upstream_ids=['CYCLE-ROOT-2'],
      last_modified=datetime.datetime(2023, 8, 14)).put()

  osv.UpstreamGroup(
      id='CYCLE-ROOT-2',
      db_id='CYCLE-ROOT-2',
      upstream_ids=['CYCLE-ROOT-1'],
      last_modified=datetime.datetime(2023, 8, 14)).put()


if __name__ == '__main__':
  # The datastore emulator needs to be started before main is imported
  # to make the global ndb client use the emulator.
  ds_emulator = tests.start_datastore_emulator()
  import main
  try:
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      setUp()
    main.app.run(host='127.0.0.1', port=8000, debug=False)
  finally:
    tests.stop_emulator()
