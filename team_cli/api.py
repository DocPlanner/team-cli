"""GraphQL client for TEAM AppSync API."""
import json
import sys

import requests

from team_cli.config import get_config
from team_cli.auth import require_auth, get_user_info


class APIError(Exception):
    pass


class AuthExpiredError(APIError):
    pass


def execute(query: str, variables: dict | None = None, tokens: dict | None = None) -> dict:
    """Execute a GraphQL query/mutation against AppSync.

    Args:
        query: GraphQL query string.
        variables: Query variables.
        tokens: Pre-fetched tokens dict. If None, will call require_auth().

    Returns:
        The 'data' portion of the response.

    Raises:
        AuthExpiredError: If the token is rejected (401/403).
        APIError: For other GraphQL or HTTP errors.
    """
    if tokens is None:
        tokens = require_auth()

    config = get_config()
    endpoint = config["appsync"]["endpoint"]
    id_token = tokens["id_token"]

    payload = {"query": query}
    if variables:
        payload["variables"] = variables

    resp = requests.post(
        endpoint,
        json=payload,
        headers={
            "Authorization": id_token,
            "Content-Type": "application/json",
        },
        timeout=30,
    )

    if resp.status_code in (401, 403):
        raise AuthExpiredError("Token expired or invalid. Run `team login` to re-authenticate.")

    if resp.status_code != 200:
        raise APIError(f"HTTP {resp.status_code}: {resp.text}")

    body = resp.json()

    if "errors" in body:
        errors = body["errors"]
        # Check for auth errors in GraphQL response
        for err in errors:
            err_type = err.get("errorType", "")
            if err_type in ("UnauthorizedException", "Unauthorized"):
                raise AuthExpiredError("Token expired. Run `team login` to re-authenticate.")
        messages = "; ".join(e.get("message", str(e)) for e in errors)
        raise APIError(f"GraphQL error: {messages}")

    return body.get("data", {})


def get_user_policy(tokens: dict) -> dict:
    """Fetch the user's eligible accounts and permissions.

    The TEAM backend getUserPolicy is async (fires a Lambda and returns immediately
    with policy: null). The frontend catches the result via GraphQL subscription.
    Instead, we compute the policy directly: look up each group's eligibility,
    resolve OUs to accounts, and build the combined policy.
    """
    from team_cli.queries import GET_ELIGIBILITY, GET_OU_ACCOUNTS
    user = get_user_info(tokens)

    policy_entries = []
    max_duration = 0

    for gid in [user["user_id"]] + user["group_ids"]:
        if not gid:
            continue
        data = execute(GET_ELIGIBILITY, {"id": gid}, tokens)
        elig = data.get("getEligibility")
        if not elig:
            continue

        duration = int(elig.get("duration") or 0)
        if duration > max_duration:
            max_duration = duration

        accounts = list(elig.get("accounts") or [])
        ou_ids = [ou["id"] for ou in (elig.get("ous") or [])]
        if ou_ids:
            ou_data = execute(GET_OU_ACCOUNTS, {"ouIds": ou_ids}, tokens)
            for result in (ou_data.get("getOUAccounts") or {}).get("results") or []:
                accounts.extend(result.get("accounts") or [])

        policy_entries.append({
            "accounts": accounts,
            "permissions": elig.get("permissions") or [],
            "approvalRequired": elig.get("approvalRequired", False),
            "duration": str(max_duration),
        })

    return {
        "id": user["user_id"],
        "policy": policy_entries if policy_entries else None,
        "username": user.get("username", ""),
    }


def get_requests_by_email(email: str, tokens: dict, status: dict | None = None) -> list:
    """Fetch requests for a given email, with optional status filter. Paginates automatically."""
    from team_cli.queries import REQUEST_BY_EMAIL_AND_STATUS
    items = []
    next_token = None
    while True:
        variables = {"email": email, "limit": 50}
        if status:
            variables["status"] = status
        if next_token:
            variables["nextToken"] = next_token
        data = execute(REQUEST_BY_EMAIL_AND_STATUS, variables, tokens)
        result = data.get("requestByEmailAndStatus", {})
        items.extend(result.get("items", []))
        next_token = result.get("nextToken")
        if not next_token:
            break
    return items


def get_requests_by_approver(approver_id: str, tokens: dict, status: dict | None = None) -> list:
    """Fetch requests assigned to an approver, with optional status filter. Paginates automatically."""
    from team_cli.queries import REQUEST_BY_APPROVER_AND_STATUS
    items = []
    next_token = None
    while True:
        variables = {"approverId": approver_id, "limit": 50}
        if status:
            variables["status"] = status
        if next_token:
            variables["nextToken"] = next_token
        data = execute(REQUEST_BY_APPROVER_AND_STATUS, variables, tokens)
        result = data.get("requestByApproverAndStatus", {})
        items.extend(result.get("items", []))
        next_token = result.get("nextToken")
        if not next_token:
            break
    return items


def get_request(request_id: str, tokens: dict) -> dict:
    """Fetch a single request by ID."""
    from team_cli.queries import GET_REQUESTS
    data = execute(GET_REQUESTS, {"id": request_id}, tokens)
    return data.get("getRequests", {})


def create_request(input_data: dict, tokens: dict) -> dict:
    """Create an elevation request."""
    from team_cli.queries import CREATE_REQUESTS
    data = execute(CREATE_REQUESTS, {"input": input_data}, tokens)
    return data.get("createRequests", {})


def update_request(input_data: dict, tokens: dict) -> dict:
    """Update a request (approve/reject/revoke)."""
    from team_cli.queries import UPDATE_REQUESTS
    data = execute(UPDATE_REQUESTS, {"input": input_data}, tokens)
    return data.get("updateRequests", {})


def validate_request(account_id: str, role_id: str, user_id: str, group_ids: list, tokens: dict) -> dict:
    """Validate a request before submission."""
    from team_cli.queries import VALIDATE_REQUEST
    data = execute(VALIDATE_REQUEST, {
        "accountId": account_id,
        "roleId": role_id,
        "userId": user_id,
        "groupIds": group_ids,
    }, tokens)
    return data.get("validateRequest", {})


def get_settings(tokens: dict) -> dict:
    """Fetch TEAM settings (max duration, ticket required, etc)."""
    from team_cli.queries import GET_SETTINGS
    data = execute(GET_SETTINGS, {"id": "settings"}, tokens)
    return data.get("getSettings", {})


def list_requests(filters: dict, tokens: dict) -> list:
    """Fetch requests using listRequests with DynamoDB filter. Auto-paginates."""
    from team_cli.queries import LIST_REQUESTS
    items = []
    next_token = None
    while True:
        variables = {"limit": 50}
        if filters:
            variables["filter"] = filters
        if next_token:
            variables["nextToken"] = next_token
        data = execute(LIST_REQUESTS, variables, tokens)
        result = data.get("listRequests", {})
        items.extend(result.get("items", []))
        next_token = result.get("nextToken")
        if not next_token:
            break
    return items


def get_requests_by_email_filtered(email: str, filters: dict, tokens: dict, status: dict | None = None) -> list:
    """Fetch requests by email with additional DynamoDB filter. Auto-paginates."""
    from team_cli.queries import REQUEST_BY_EMAIL_AND_STATUS_FILTERED
    items = []
    next_token = None
    while True:
        variables = {"email": email, "limit": 50}
        if status:
            variables["status"] = status
        if filters:
            variables["filter"] = filters
        if next_token:
            variables["nextToken"] = next_token
        data = execute(REQUEST_BY_EMAIL_AND_STATUS_FILTERED, variables, tokens)
        result = data.get("requestByEmailAndStatus", {})
        items.extend(result.get("items", []))
        next_token = result.get("nextToken")
        if not next_token:
            break
    return items


def get_session(request_id: str, tokens: dict) -> dict | None:
    """Fetch session by ID (same ID as the request). Returns None if no session."""
    from team_cli.queries import GET_SESSIONS
    try:
        data = execute(GET_SESSIONS, {"id": request_id}, tokens)
        return data.get("getSessions")
    except APIError:
        return None


def get_logs(query_id: str, tokens: dict) -> list:
    """Fetch CloudTrail events for a session's queryId."""
    from team_cli.queries import GET_LOGS
    data = execute(GET_LOGS, {"queryId": query_id}, tokens)
    return data.get("getLogs") or []
