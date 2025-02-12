"""
Download all of the copyright files for packages in main in Debian unstable.

This:

Parses https://metadata.ftp-master.debian.org/changelogs/filelist.yaml.xz 
    to identify the files to retrieve
Generates a curl configuration to download the URLs
Executes curl to download the URLs in parallel
"""

import os
import argparse
import yaml
import lzma
import urllib.request
import subprocess
from typing import List, Optional, Dict


class Error(Exception):
  """General purpose error class."""


def download_url_to_directory(url: str,
                              directory: str,
                              filename: Optional[str] = None) -> Optional[str]:
  """
    Downloads a URL to a specified directory.

    Args:
        url (str): The URL to download.
        directory (str): The directory to save the file to.
        filename (str, optional): The filename to use. If None, the filename
                                   is extracted from the URL. Defaults to None.

    Returns:
        str: The full path to the downloaded file, or None on error.
  """
  try:
    if not os.path.exists(directory):
      os.makedirs(directory)

    if filename is None:
      filename = os.path.basename(urllib.parse.urlsplit(url).path)

    filepath = os.path.join(directory, filename)

    urllib.request.urlretrieve(url, filepath)
    return filepath

  except urllib.error.URLError as e:
    print(f'Error downloading {url}: {e}')
    return None
  except OSError as e:  # Catch directory creation/file writing errors.
    print(f'OS Error: {e}')
    return None
  except Exception as e:  # Catch any other unexpected error.
    print(f'An unexpected error occurred: {e}')
    return None


def extract_unstable_copyright(filelist: str) -> Dict:
  """
    Extracts the 'unstable_copyright' entry for each package 
        from an xz-compressed YAML file.

    Args:
        filelist (str): The path to the xz-compressed YAML filelist

    Returns:
        A dictionary where keys are package names and values are 
            their 'unstable_copyright' entries, or None if no unstable 
            copyright is found.
  """
  try:
    with lzma.open(filelist, 'rt', encoding='utf-8') as f:
      data = yaml.safe_load(f)

    results = {}
    for package, versions in data.items():
      if 'unstable' in versions:
        entries = versions['unstable']
        for entry in entries:
          if entry.endswith('unstable_copyright'):
            results[package] = entry
            break  # Found it, no need to continue checking this package.

    return results

  except FileNotFoundError:
    print(f"Error: File not found at {filelist}")
    return None
  except lzma.LZMAError as e:
    print(f"Error: LZMA decompression failed: {e}")
    return None
  except yaml.YAMLError as e:
    print(f"Error: YAML parsing failed: {e}")
    return None
  except Exception as e:
    print(f"An unexpected error occurred: {e}")
    return None


def generate_curl_configuration(filelist: List[str]):
  """
    Generates a curl configuration to download all of the files in filelist.

    --output filename
    url = https://url

    Args:
        filelist (List[str]): a list of files to download.
  """

  url_base = 'https://metadata.ftp-master.debian.org/changelogs'

  with open('/tmp/curl_configuration', 'w') as curl_config:
    curl_config.writelines([
        '--output ' + path + '\n' + 'url = ' + os.path.join(url_base, path) +
        '\n' for path in filelist
    ])


def execute_curl(configuration: str, directory: str):
  """
    Execute curl with the supplied configuration in the specified directory.

    Args:
        configuration (str): path to configuration file.
        directory (str): path to set current working directory to.
 """

  os.makedirs(directory)
  _ = subprocess.run(
      ['curl', '--parallel', '--create-dirs', '--config', configuration],
      cwd=directory,
      check=True)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('work_dir')
  args = parser.parse_args()

  download_url_to_directory(
      'https://metadata.ftp-master.debian.org/changelogs/filelist.yaml.xz',
      '/tmp')
  unstable_package_copyright_files = extract_unstable_copyright(
      '/tmp/filelist.yaml.xz')
  if unstable_package_copyright_files is None:
    raise Error('Unexpected result determining files to download')
  generate_curl_configuration(
      f for f in unstable_package_copyright_files.values()
      if f.startswith('main/'))
  with open("/tmp/curl_configuration") as curl_configuration:
    if len(curl_configuration.readlines()) < 80000:
      raise Error('Unexpectly small curl configuration')
  execute_curl('/tmp/curl_configuration', args.work_dir)


if __name__ == '__main__':
  main()
