import http.server
import json
import logging
import os
class MockDataHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            with open('testdata/curl.json', 'r') as f:
                data = json.load(f)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Last-Modified', 'Fri, 01 Jan 2021 00:00:00 GMT')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode('utf-8'))
        except:
            self.send_error(404, 'File not found')
    def do_HEAD(self):
        try:
            with open('testdata/curl.json', 'r') as f:
                json.load(f)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Last-Modified', 'Fri, 01 Jan 2021 00:00:00 GMT')
            self.end_headers()
        except:
           self.send_error(404, 'File not found')