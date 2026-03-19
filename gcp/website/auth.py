"""Authentication handlers."""
import os
import secrets
from functools import wraps
import requests

from flask import Blueprint, request, session, redirect, url_for, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

blueprint = Blueprint('auth', __name__)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/"
                        ".well-known/openid-configuration")

# Easy bypass for local development testing
BYPASS_OAUTH_FOR_LOCAL_DEV = os.environ.get("BYPASS_OAUTH_FOR_LOCAL_DEV",
                                            "False").lower() in ("true", "1",
                                                                 "t")


def get_google_provider_cfg():
  """Get Google provider configuration."""
  return requests.get(GOOGLE_DISCOVERY_URL, timeout=10).json()


@blueprint.route("/login")
def login():
  """Login route."""
  if BYPASS_OAUTH_FOR_LOCAL_DEV:
    session['user_email'] = 'dev@google.com'
    return redirect(url_for('triage_handlers.triage_index'))

  if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    return jsonify({
        'error': 'OAuth credentials not configured. '
                 'Set GOOGLE_OAUTH_CLIENT_ID and '
                 'GOOGLE_OAUTH_CLIENT_SECRET env vars or '
                 'enable BYPASS_OAUTH_FOR_LOCAL_DEV.'
    }), 500

  google_provider_cfg = get_google_provider_cfg()
  authorization_endpoint = google_provider_cfg["authorization_endpoint"]

  state = secrets.token_urlsafe(16)
  session['oauth_state'] = state

  redirect_uri = url_for('auth.callback', _external=True)
  # Ensure redirect_uri uses https if the app is accessed over https
  # (for environments behind load balancers without proxyfix)
  if request.headers.get(
      'X-Forwarded-Proto',
      'http') == 'https' and redirect_uri.startswith('http://'):
    redirect_uri = redirect_uri.replace('http://', 'https://', 1)

  request_uri = (f"{authorization_endpoint}?response_type=code"
                 f"&client_id={GOOGLE_CLIENT_ID}"
                 f"&redirect_uri={redirect_uri}"
                 f"&scope=openid%20email%20profile"
                 f"&state={state}"
                 f"&access_type=offline")

  return redirect(request_uri)


@blueprint.route("/auth/callback")
def callback():
  """Auth callback route."""
  if request.args.get('state') != session.get('oauth_state'):
    return jsonify({'error': 'Invalid state parameter'}), 400

  code = request.args.get("code")
  google_provider_cfg = get_google_provider_cfg()
  token_endpoint = google_provider_cfg["token_endpoint"]

  redirect_uri = url_for('auth.callback', _external=True)
  if request.headers.get(
      'X-Forwarded-Proto',
      'http') == 'https' and redirect_uri.startswith('http://'):
    redirect_uri = redirect_uri.replace('http://', 'https://', 1)

  token_url = token_endpoint
  token_data = {
      "code": code,
      "client_id": GOOGLE_CLIENT_ID,
      "client_secret": GOOGLE_CLIENT_SECRET,
      "redirect_uri": redirect_uri,
      "grant_type": "authorization_code",
  }

  token_response = requests.post(token_url, data=token_data, timeout=10)
  token_json = token_response.json()

  if "id_token" not in token_json:
    return jsonify({
        'error': 'Failed to obtain ID token. '
                 'Maybe credentials mismatch or invalid code.'
    }), 400

  token = token_json["id_token"]

  try:
    # Verify the token
    client_request = google_requests.Request()
    id_info = id_token.verify_oauth2_token(token, client_request,
                                           GOOGLE_CLIENT_ID)

    # The oauth only allows users to login with accounts that have
    # access to the GCP project
    session['user_email'] = id_info.get("email")
    return redirect(url_for('triage_handlers.triage_index'))

  except ValueError:
    return jsonify({'error': 'Invalid token'}), 400


@blueprint.route("/logout")
def logout():
  session.pop('user_email', None)
  return redirect(url_for('triage_handlers.triage_index'))


def require_google_account(f):
  """Decorator to require Google account."""

  @wraps(f)
  def decorated_function(*args, **kwargs):
    if BYPASS_OAUTH_FOR_LOCAL_DEV:
      return f(*args, **kwargs)

    if 'user_email' not in session:
      return redirect(url_for('auth.login'))

    return f(*args, **kwargs)

  return decorated_function
