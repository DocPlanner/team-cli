"""OAuth2 Authorization Code + PKCE flow via Cognito Hosted UI."""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

import requests

from team_cli.config import (
    COGNITO_REDIRECT_URI, CALLBACK_PORT,
    get_config, save_tokens, load_tokens, clear_tokens,
)


def _generate_pkce():
    """Generate PKCE code_verifier and code_challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _parse_id_token(id_token: str) -> dict:
    """Decode JWT payload without verification (tokens come from Cognito over HTTPS)."""
    payload = id_token.split(".")[1]
    # Add padding
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload))


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth callback."""

    auth_code = None
    error = None

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if "code" in params:
            _CallbackHandler.auth_code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h2>Authenticated! You can close this tab.</h2></body></html>")
        else:
            _CallbackHandler.error = params.get("error", ["unknown"])[0]
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body><h2>Error: {_CallbackHandler.error}</h2></body></html>".encode())

    def log_message(self, format, *args):
        pass  # Suppress request logging


def _exchange_code(code: str, verifier: str, domain: str, client_id: str) -> dict:
    """Exchange authorization code for tokens at Cognito token endpoint."""
    token_url = f"{domain}/oauth2/token"
    resp = requests.post(token_url, data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": COGNITO_REDIRECT_URI,
        "code_verifier": verifier,
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    if resp.status_code != 200:
        raise RuntimeError(f"Token exchange failed ({resp.status_code}): {resp.text}")

    return resp.json()


def _refresh_access_token(refresh_token: str, domain: str, client_id: str) -> dict | None:
    """Use refresh_token to get new access/id tokens."""
    token_url = f"{domain}/oauth2/token"
    resp = requests.post(token_url, data={
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    if resp.status_code != 200:
        return None

    return resp.json()


def login(silent: bool = False) -> dict:
    """Run the full OAuth2 login flow. Returns token data with parsed claims.

    Args:
        silent: If True, suppress interactive output (for auto-refresh callers).
    """
    config = get_config()
    cognito = config["cognito"]
    domain = cognito["domain"]
    client_id = cognito["client_id"]
    idp = cognito.get("identity_provider", "IDC")
    scopes = cognito.get("scopes", [
        "aws.cognito.signin.user.admin", "email", "openid", "phone", "profile"
    ])

    verifier, challenge = _generate_pkce()

    # Reset handler state
    _CallbackHandler.auth_code = None
    _CallbackHandler.error = None

    # Start local callback server
    server = HTTPServer(("127.0.0.1", CALLBACK_PORT), _CallbackHandler)
    server_thread = threading.Thread(target=server.handle_request, daemon=True)
    server_thread.start()

    # Build authorization URL
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": COGNITO_REDIRECT_URI,
        "scope": " ".join(scopes),
        "identity_provider": idp,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
    auth_url = f"{domain}/oauth2/authorize?{urlencode(auth_params)}"

    if not silent:
        print("Opening browser for authentication...")
        print(f"If browser doesn't open, visit:\n{auth_url}\n")

    # Open browser
    if sys.platform == "darwin":
        subprocess.Popen(["open", auth_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        webbrowser.open(auth_url)

    # Wait for callback
    server_thread.join(timeout=120)
    server.server_close()

    if _CallbackHandler.error:
        raise RuntimeError(f"Authentication failed: {_CallbackHandler.error}")
    if not _CallbackHandler.auth_code:
        raise RuntimeError("Authentication timed out (120s). Try again.")

    # Exchange code for tokens
    tokens = _exchange_code(_CallbackHandler.auth_code, verifier, domain, client_id)

    # Parse claims from id_token
    claims = _parse_id_token(tokens["id_token"])
    tokens["claims"] = claims

    # Save tokens
    save_tokens(tokens)

    return tokens


def get_valid_tokens() -> dict | None:
    """Get valid tokens, refreshing if needed. Returns None if login required."""
    tokens = load_tokens()
    if not tokens:
        return None

    claims = tokens.get("claims", {})
    exp = claims.get("exp", 0)

    # Check if id_token is still valid (with 60s buffer)
    if time.time() < (exp - 60):
        return tokens

    # Try refresh
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        return None

    config = get_config()
    cognito = config["cognito"]
    refreshed = _refresh_access_token(
        refresh_token, cognito["domain"], cognito["client_id"]
    )
    if not refreshed:
        clear_tokens()
        return None

    # Merge: refresh response doesn't include refresh_token
    refreshed["refresh_token"] = refresh_token
    refreshed["claims"] = _parse_id_token(refreshed["id_token"])
    save_tokens(refreshed)
    return refreshed


def require_auth() -> dict:
    """Get valid tokens or trigger login. Returns tokens dict."""
    tokens = get_valid_tokens()
    if tokens:
        return tokens
    return login()


def get_user_info(tokens: dict) -> dict:
    """Extract user info from token claims."""
    claims = tokens.get("claims", {})
    return {
        "email": claims.get("email", ""),
        "username": claims.get("cognito:username", claims.get("email", "")),
        "user_id": claims.get("custom:userId", claims.get("userId", claims.get("sub", ""))),
        "group_ids": [g for g in (claims.get("custom:groupIds") or claims.get("groupIds") or "").split(",") if g],
        "groups": claims.get("cognito:groups", []),
    }
