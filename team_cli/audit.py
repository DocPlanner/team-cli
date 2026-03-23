"""Audit logic: fetch elevation requests, correlate sessions and CloudTrail events."""
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable

from team_cli.api import (
    list_requests, get_requests_by_email_filtered,
    get_session, get_logs, APIError, AuthExpiredError,
)


def _build_filter(account: str | None, role: str | None, from_date: str | None,
                  to_date: str | None, status: str | None) -> dict:
    """Build a DynamoDB filter expression from audit arguments."""
    f = {}
    if account:
        if account.isdigit() and len(account) == 12:
            f["accountId"] = {"eq": account}
        else:
            f["accountName"] = {"eq": account}
    if role:
        f["role"] = {"eq": role}
    if status:
        f["status"] = {"eq": status}
    if from_date and to_date:
        f["startTime"] = {"between": [
            f"{from_date}T00:00:00Z",
            f"{to_date}T23:59:59Z",
        ]}
    elif from_date:
        f["startTime"] = {"ge": f"{from_date}T00:00:00Z"}
    elif to_date:
        f["startTime"] = {"le": f"{to_date}T23:59:59Z"}
    return f


def fetch_audit_data(
    tokens: dict,
    actor: str | None,
    account: str | None,
    role: str | None,
    from_date: str | None,
    to_date: str | None,
    status: str,
    limit: int,
    include_logs: bool,
    on_progress: Callable | None = None,
) -> list[dict]:
    """Fetch elevation requests with optional CloudTrail events.

    Args:
        tokens: Auth tokens dict.
        actor: Requester email filter.
        account: Account ID or name filter.
        role: Permission set name filter.
        from_date: Start date (YYYY-MM-DD).
        to_date: End date (YYYY-MM-DD).
        status: Request status filter.
        limit: Max requests to return.
        include_logs: Whether to fetch CloudTrail events.
        on_progress: Callback(current, total, request) for progress reporting.

    Returns:
        List of audit result dicts.
    """
    filters = _build_filter(account, role, from_date, to_date, status)

    try:
        if actor:
            # Use indexed query — faster
            status_filter = {"eq": status} if status else None
            requests = get_requests_by_email_filtered(actor, filters, tokens, status=status_filter)
        else:
            # Scan with server-side filter
            if not filters:
                filters = {}
            if status and "status" not in filters:
                filters["status"] = {"eq": status}
            requests = list_requests(filters, tokens)
    except AuthExpiredError:
        raise
    except APIError as e:
        err = str(e).lower()
        if "unauthorized" in err or "not authorized" in err:
            print("Audit requires Auditors group membership. Contact your TEAM admin.",
                  file=sys.stderr)
            sys.exit(1)
        raise

    # Sort by startTime descending (most recent first)
    requests.sort(key=lambda r: r.get("startTime") or "", reverse=True)
    requests = requests[:limit]

    results = []
    total = len(requests)
    for i, req in enumerate(requests):
        if on_progress:
            on_progress(i + 1, total, req)

        events = None
        event_count = None

        if include_logs:
            session = get_session(req["id"], tokens)
            query_id = session.get("queryId") if session else None
            if query_id:
                events = get_logs(query_id, tokens)
                event_count = len(events)
            else:
                events = []
                event_count = 0

        # Compute duration_hours from duration field (stored as string of hours)
        duration_hours = None
        if req.get("duration"):
            try:
                duration_hours = int(req["duration"])
            except (ValueError, TypeError):
                pass

        results.append({
            "request": {
                "id": req.get("id"),
                "email": req.get("email"),
                "account_id": req.get("accountId"),
                "account_name": req.get("accountName"),
                "role": req.get("role"),
                "justification": req.get("justification"),
                "ticket": req.get("ticketNo") or None,
                "status": req.get("status"),
                "duration_hours": duration_hours,
                "start_time": req.get("startTime"),
                "end_time": req.get("endTime"),
                "approver": req.get("approver"),
                "created_at": req.get("createdAt"),
            },
            "cloudtrail_events": [
                {
                    "event_time": e.get("eventTime"),
                    "event_name": e.get("eventName"),
                    "event_source": e.get("eventSource"),
                    "event_id": e.get("eventID"),
                }
                for e in events
            ] if events is not None else None,
            "event_count": event_count,
        })

    return results


def format_audit_json(results: list[dict]) -> str:
    """Format results as JSON for AI/pipe consumption."""
    return json.dumps(results, indent=2, default=str)


def format_audit_table(results: list[dict]) -> str:
    """Format results as human-readable output."""
    if not results:
        return "No matching elevation requests found."

    lines = [f"Elevation Requests ({len(results)} results)", "\u2500" * 30, ""]

    for entry in results:
        req = entry["request"]
        email = req.get("email") or "?"
        acct_name = req.get("account_name") or "?"
        acct_id = req.get("account_id") or "?"
        role = req.get("role") or "?"
        status = req.get("status") or "?"
        duration = req.get("duration_hours")
        duration_str = f"{duration}h" if duration else "?"
        start = _format_time(req.get("start_time"))
        end = _format_time(req.get("end_time"))
        justification = req.get("justification") or ""
        ticket = req.get("ticket") or ""
        approver = req.get("approver") or ""

        lines.append(f"{email} | {acct_name} ({acct_id}) | {role}")
        lines.append(f"  Status: {status} | Duration: {duration_str} | {start} \u2192 {end}")
        lines.append(f"  Justification: {justification}")

        detail_parts = []
        if ticket:
            detail_parts.append(f"Ticket: {ticket}")
        if approver:
            detail_parts.append(f"Approver: {approver}")
        if detail_parts:
            lines.append(f"  {' | '.join(detail_parts)}")

        events = entry.get("cloudtrail_events")
        event_count = entry.get("event_count")
        if events is not None:
            lines.append(f"  CloudTrail events: {event_count}")
            if events:
                # Group by source, then count event names
                by_source = {}
                for ev in events:
                    src = ev.get("event_source") or "unknown"
                    name = ev.get("event_name") or "unknown"
                    by_source.setdefault(src, []).append(name)
                for src, names in sorted(by_source.items()):
                    counts = Counter(names)
                    parts = [f"{name} (x{count})" if count > 1 else name
                             for name, count in counts.most_common()]
                    lines.append(f"    {src}: {', '.join(parts)}")

        lines.append("")

    return "\n".join(lines)


def _format_time(iso_str: str | None) -> str:
    """Format an ISO time string to a short readable form."""
    if not iso_str:
        return "?"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, AttributeError):
        return iso_str
