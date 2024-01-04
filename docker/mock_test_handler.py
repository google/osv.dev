import http.server
import json


class MockDataHandler(http.server.BaseHTTPRequestHandler):
  """Mock data handler for testing."""
  last_modified = 'Tue, 13 Jun 2023 00:00:00 GMT'
  file_path = 'testdata/rest_test.json'

  def do_GET(self):
    """Serve a mock GET request."""
    try:
      with open(self.file_path, 'r') as f:
        data = json.load(f)
      
      if (self.path != '/'):
        found = False
        # find the vulnerability to mock serve the new page
        for vuln in data:
            if vuln['id'] == (self.path.split('/')[-1]).split('.json')[0]:
                data = vuln
                found = True
                break
        if not found:
            raise Exception
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.send_header('Last-Modified', self.last_modified)
      self.end_headers()
      self.wfile.write(json.dumps(data).encode('utf-8'))
    except Exception:
      self.send_error(404, 'File not found')

  def do_HEAD(self):
    """Serve a mock HEAD request."""
    try:
      with open(self.file_path, 'r') as f:
        json.load(f)
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.send_header('Last-Modified', self.last_modified)
      self.end_headers()
    except Exception:
      self.send_error(404, 'File not found')
