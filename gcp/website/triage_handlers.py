"""Triage handlers."""
import logging
import re
import requests

from flask import Blueprint, request, jsonify, render_template
from google.cloud import storage

import auth

blueprint = Blueprint('triage_handlers', __name__)


@blueprint.before_request
@auth.require_google_account
def require_oauth():
  """Require OAuth for all triage handlers."""
  return None


_CVE_ID_REGEX = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
_STORAGE_CLIENT = None


def get_storage_client():
  """Get storage client."""
  global _STORAGE_CLIENT  # pylint: disable=global-statement
  if _STORAGE_CLIENT is None:
    _STORAGE_CLIENT = storage.Client()
  return _STORAGE_CLIENT


@blueprint.route('/triage')
def triage_index():
  """Triage index."""
  return render_template('triage.html')


GCS_SOURCE_CONFIG = {
    'test-nvd': {
        'bucket': 'osv-test-cve-osv-conversion',
        'path_template': 'nvd-osv/{id}.json'
    },
    'test-cve5': {
        'bucket': 'osv-test-cve-osv-conversion',
        'path_template': 'cve5/{id}.json'
    },
    'test-osv': {
        'bucket': 'osv-test-cve-osv-conversion',
        'path_template': 'osv-output/{id}.json'
    },
    'test-nvd-metrics': {
        'bucket': 'osv-test-cve-osv-conversion',
        'path_template': 'nvd-osv/{id}.metrics.json'
    },
    'test-cve5-metrics': {
        'bucket': 'osv-test-cve-osv-conversion',
        'path_template': 'cve5/{id}.metrics.json'
    },
    'prod-nvd': {
        'bucket': 'cve-osv-conversion',
        'path_template': 'nvd-osv/{id}.json'
    },
    'prod-cve5': {
        'bucket': 'cve-osv-conversion',
        'path_template': 'cve5/{id}.json'
    },
    'prod-osv': {
        'bucket': 'cve-osv-conversion',
        'path_template': 'osv-output/{id}.json'
    },
    'prod-nvd-metrics': {
        'bucket': 'cve-osv-conversion',
        'path_template': 'nvd-osv/{id}.metrics.json'
    },
    'prod-cve5-metrics': {
        'bucket': 'cve-osv-conversion',
        'path_template': 'cve5/{id}.metrics.json'
    },
}


@blueprint.route('/triage/proxy')
def triage_proxy():
  """Proxy to fetch files from GCS buckets or external APIs securely."""
  source = request.args.get('source')
  vuln_id = request.args.get('id')

  if not source or not vuln_id:
    return jsonify({'error': 'Missing source or id parameters'}), 400

  # Validate CVE ID format
  if not re.match(_CVE_ID_REGEX, vuln_id):
    return jsonify({'error': 'Invalid ID format'}), 400

  # Handle GCS sources
  if source in GCS_SOURCE_CONFIG:
    config = GCS_SOURCE_CONFIG[source]
    bucket_name = config['bucket']
    path = config['path_template'].format(id=vuln_id.upper())

    try:
      bucket = get_storage_client().bucket(bucket_name)
      blob = bucket.blob(path)

      if not blob.exists():
        return jsonify({'error': 'File not found'}), 404

      content = blob.download_as_text()
      return content, 200, {'Content-Type': 'application/json'}

    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.error('Error fetching from GCS (%s): %s', source, e)
      return jsonify({'error': 'Internal server error'}), 500

  # Handle API sources
  url = None
  if source == 'cve':
    # Construct GitHub raw URL for CVE data
    match = re.match(r'^CVE-(\d{4})-(\d+)$', vuln_id, re.IGNORECASE)
    if not match:
      return jsonify({'error': 'Invalid ID format'}), 400
    year = match.group(1)
    seq = match.group(2)
    seq_prefix = seq[:-3] if len(seq) > 3 else '0'
    url = (f'https://raw.githubusercontent.com/CVEProject/cvelistV5/'
           f'refs/heads/main/cves/{year}/{seq_prefix}xxx/'
           f'{vuln_id.upper()}.json')
  elif source == 'nvd':
    url = (f'https://services.nvd.nist.gov/rest/json/cves/2.0'
           f'?cveId={vuln_id.upper()}')
  else:
    return jsonify({'error': 'Invalid source'}), 400

  try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text, 200, {'Content-Type': 'application/json'}
  except Exception as e:
    logging.error('Error fetching from external API (%s): %s', source, e)
    return jsonify({'error': 'Error fetching from external API'}), 500
