import http.server
import json
class MockDataHandler(http.server.BaseHTTPRequestHandler):

    last_modified = 'Tue, 13 Jun 2023 00:00:00 GMT'
    file_path = 'testdata/rest_test.json'

    def do_GET(self):
        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Last-Modified', self.last_modified)
            self.end_headers()
            self.wfile.write(json.dumps(data).encode('utf-8'))
        except:
            self.send_error(404, 'File not found')
    def do_HEAD(self):
        try:
            with open(self.file_path, 'r') as f:
                json.load(f)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Last-Modified', self.last_modified)
            self.end_headers()
        except:
           self.send_error(404, 'File not found')