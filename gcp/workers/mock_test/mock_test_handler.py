"""Mock Data Handler for HTTP Request Testing"""
from __future__ import annotations

import http.server
import json
import os
from typing import Any, Dict, List, Optional, Union # Added necessary types

TEST_DATA_DIR: str = os.path.dirname(os.path.abspath(__file__))


class MockDataHandler(http.server.BaseHTTPRequestHandler):
  """Mock data handler for testing."""
  # Class attributes with types
  last_modified: str = 'Mon, 01 Jan 2024 00:00:00 GMT'
  file_path: str = 'rest_test.json' # Default file to load

  # Instance attributes that will be initialized
  # self.data can be a list of vulnerabilities or a single vulnerability dict
  data: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None
  # cve_count is len(self.data) when self.data is a list, or -1 if not loaded/single
  cve_count: int = -1


  def load_file(self, path_to_load: str = file_path) -> None: # Renamed path, default uses class attr
    """Load the JSON data file."""
    # It's generally better to use instance variable for file_path if it can change per instance,
    # but here it's used as a default for the parameter, referencing the class attribute.
    # This is okay if file_path is meant to be a class-wide default.
    # If an instance could have a different file_path, it should be an instance variable.
    # For now, assuming class attribute `file_path` is the intended default.

    # Ensure TEST_DATA_DIR is correctly located relative to this file.
    # If tests run from a different CWD, this might fail.
    # A common pattern is `os.path.join(os.path.dirname(__file__), 'testdata', path_to_load)`
    # The current TEST_DATA_DIR definition seems to do this.
    full_file_path = os.path.join(TEST_DATA_DIR, path_to_load)
    try:
      with open(full_file_path, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
        # Check if loaded_data is a list (expected for initial load of multiple vulns)
        if isinstance(loaded_data, list):
            self.data = loaded_data
            self.cve_count = len(loaded_data)
        elif isinstance(loaded_data, dict): # Could also be a single object if file contains one
            self.data = loaded_data
            self.cve_count = 1 # Or 0 or specific logic if single dict means one item
        else:
            # Data is not in expected format (list or dict)
            self.send_error(500, f"Test data file {path_to_load} has unexpected format.")
            self.data = None
            self.cve_count = -1
            return
    except FileNotFoundError:
      self.send_error(404, f"Test data file not found: {path_to_load}")
      self.data = None
      self.cve_count = -1
    except json.JSONDecodeError:
      self.send_error(500, f"Error decoding JSON from test data file: {path_to_load}")
      self.data = None
      self.cve_count = -1
    except Exception: # Catch other potential errors during file loading
      self.send_error(500, f"An unexpected error occurred while loading file: {path_to_load}")
      self.data = None
      self.cve_count = -1


  def do_GET(self) -> None:  # pylint: disable=invalid-name
    """Serve a mock GET request."""
    if self.data is None or self.cve_count == -1: # Ensure data is loaded
      self.load_file(self.file_path) # Load default file if not already loaded
      if self.data is None: # If loading failed, load_file would have sent error.
          return

    current_data_to_serve: Any = self.data # Data to be served, might be list or dict

    try:
      if self.path != '/': # Request for a specific vulnerability ID
        # Path is like "/CVE-XXXX-XXXX.json" or "/PYSEC-XXXX-XXXX"
        # Extract ID from path: (self.path.split('/')[-1]).split('.json')[0]
        requested_id_part = self.path.split('/')[-1]
        requested_id = os.path.splitext(requested_id_part)[0] # Handles .json or no extension

        if isinstance(self.data, list): # If current data is a list of vulns
          found_vuln: Optional[Dict[str, Any]] = None
          for vuln_item in self.data: # Renamed vuln
            if isinstance(vuln_item, dict) and vuln_item.get('id') == requested_id:
              found_vuln = vuln_item
              break

          if found_vuln:
            current_data_to_serve = found_vuln
          else:
            self.send_error(404, f'Vulnerability ID {requested_id} not found in loaded data.')
            return
        elif isinstance(self.data, dict): # If current data is a single vuln dict
            # Check if this single loaded vuln matches the requested ID
            if self.data.get('id') != requested_id:
                self.send_error(404, f'Vulnerability ID {requested_id} does not match loaded single data.')
                return
            # current_data_to_serve is already self.data (the single dict)
        else: # self.data is None or unexpected type
            self.send_error(500, 'Mock server data not loaded correctly.')
            return

      # If self.path == '/', serve self.data as is (could be list or dict)
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.send_header('Last-Modified', self.last_modified) # Class attribute
      self.end_headers()
      self.wfile.write(json.dumps(current_data_to_serve).encode('utf-8'))
    except Exception: # Broad catch for unexpected errors during response generation
      # Log the exception here for debugging if needed
      self.send_error(500, 'Internal error processing GET request.')


  def do_HEAD(self) -> None:  # pylint: disable=invalid-name
    """Serve a mock HEAD request."""
    # Data loading logic might not be strictly necessary for HEAD if only headers are sent.
    # However, if validation or checks based on data existence are needed, load it.
    # For now, assume it's not strictly needed for HEAD to reduce I/O if file isn't used.
    # if self.cve_count == -1: # Or self.data is None
    #   self.load_file(self.file_path)
    #   if self.data is None: return # load_file sent error

    self.send_response(200)
    self.send_header('Content-Type', 'application/json')
    self.send_header('Last-Modified', self.last_modified) # Class attribute
    self.end_headers()

  # Overriding log_message from BaseHTTPRequestHandler
  # format is the log string format, args are the values for the format string.
  def log_message(self, format_str: str, *args: Any) -> None:  # pylint: disable=redefined-builtin
    # Disable logging for successful (200) responses to reduce noise during tests.
    # args[1] is typically the status code string in default log formats.
    if len(args) > 1 and args[1] == '200': # Check if second arg (status code) is '200'
      return # Suppress log message
    super().log_message(format_str, *args) # Call base class method for other messages
