"""Mock Data Handler for HTTP Request Testing"""
import http.server
import json
import os
#/usr/local/google/home/jesslowe/jess-osv/osv.dev/docker/mock_test/rest_test.json
#https://github.com/jess-lowe/osv.dev/blob/rest-message-pass/docker/mock_test/rest_test.json
#docker/mock_test/rest_test.json

TEST_DATA_DIR = os.path.dirname(os.path.abspath(__file__))

class MockDataHandler(http.server.BaseHTTPRequestHandler):
  """Mock data handler for testing."""
  last_modified = 'Tue, 13 Jun 2023 00:00:00 GMT'
  file_path = 'rest_test.json'
  cve_count = -1
  data = None

  def load_file(self, path=file_path):
    """Load the file."""
    try:
        with open(os.path.join(TEST_DATA_DIR, path), 'r') as f:
            self.data = json.load(f)
            self.cve_count = len(self.data)
    except Exception:
        self.send_error(404, 'File not found')  
  
  def do_GET(self):  # pylint: disable=invalid-name
    """Serve a mock GET request."""
    if self.cve_count == -1:
        self.load_file(self.file_path)
    try:
      if self.path != '/':
        found = False
        # find the vulnerability to mock serve the new page
        for vuln in self.data:
          if vuln['id'] == (self.path.split('/')[-1]).split('.json')[0]:
            self.data = vuln
            found = True
            break
        if not found:
          raise FileNotFoundError
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.send_header('Last-Modified', self.last_modified)
      self.end_headers()
      self.wfile.write(json.dumps(self.data).encode('utf-8'))
    except Exception:
      self.send_error(404, 'File not found')

  def do_HEAD(self):  # pylint: disable=invalid-name
    """Serve a mock HEAD request."""
    if self.cve_count == -1:
      self.load_file(self.file_path)
    self.send_response(200)
    self.send_header('Content-Type', 'application/json')
    self.send_header('Last-Modified', self.last_modified)
    self.end_headers()
