#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import test_server

_PORT = 8080

def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} path/to/credential.json')
        sys.exit(1)

    credential_path = sys.argv[1]

    # Ensure Docker image is pulled
    subprocess.run(
        ['docker', 'pull', 'gcr.io/endpoints-release/endpoints-runtime:2'],
        check=True)

    print("Starting test server...")
    server = test_server.start(credential_path, port=_PORT)
    
    # Wait for server to start up
    time.sleep(10)

    try:
        # Determine API URL
        if os.getenv('CLOUDBUILD'):
            host = test_server.get_cloudbuild_esp_host()
        else:
            host = 'localhost'
            
        api_base_url = f"{host}:{_PORT}"
        print(f"Running Go tests against {api_base_url}")
        
        env = os.environ.copy()
        env['OSV_API_BASE_URL'] = api_base_url

        # Go tests path
        # Assuming this script is in gcp/api/
        go_test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tools/apitester'))
        
        cmd = ['go', 'test', './...']
        print(f"Executing: {' '.join(cmd)} in {go_test_dir}")
        
        subprocess.run(cmd, cwd=go_test_dir, env=env, check=True)
        
    finally:
        print("Stopping test server...")
        server.stop()

if __name__ == '__main__':
    main()
