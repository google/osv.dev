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
"""setup.py for OSV."""
import setuptools

with open('README.md', 'r') as fh:
  long_description = fh.read()

setuptools.setup(
    name='osv',
    version='0.0.14',
    author='OSV authors',
    author_email='osv-discuss@googlegroups.com',
    description='Open Source Vulnerabilities library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/google/osv',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    install_requires=[
        'google-cloud-ndb',
        'pygit2',
        'PyYAML',
        'semver',
    ],
    package_dir={
        '': '.',
    },
    python_requires='>=3.7',
    zip_safe=False,
)
