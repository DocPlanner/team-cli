"""Interactive prompts for multi-account request flow."""
import sys
import threading
import time
from datetime import datetime, timezone


def spinner(message: str, stop_event: threading.Event) -> None:
    """Show a spinner while waiting."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not stop_event.is_set():
        sys.stderr.write(f"\r{chars[i % len(chars)]} {message}")
        sys.stderr.flush()
        i += 1
        stop_event.wait(0.1)
    sys.stderr.write(f"\r\033[2K")
    sys.stderr.flush()


def with_spinner(message: str):
    """Context manager that shows a spinner."""
    class SpinnerCtx:
        def __enter__(self):
            self.stop = threading.Event()
            self.thread = threading.Thread(target=spinner, args=(message, self.stop), daemon=True)
            self.thread.start()
            return self

        def __exit__(self, *args):
            self.stop.set()
            self.thread.join()
    return SpinnerCtx()


def select_accounts(accounts: list[dict]) -> list[dict]:
    """Interactive multi-select for accounts."""
    try:
        from InquirerPy import inquirer
    except ImportError:
        print("InquirerPy not installed. Use --account flag instead, or: pip install InquirerPy")
        sys.exit(1)

    choices = [
        {"name": f"{a['name']} ({a['id']})", "value": a}
        for a in accounts
    ]

    selected = inquirer.checkbox(
        message="Select accounts (space to toggle, enter to confirm):",
        choices=choices,
        validate=lambda result: len(result) > 0,
        invalid_message="Select at least one account",
    ).execute()

    return selected


def select_role(permissions: list[dict]) -> dict:
    """Interactive single-select for role/permission set."""
    try:
        from InquirerPy import inquirer
    except ImportError:
        print("InquirerPy not installed. Use --role flag instead, or: pip install InquirerPy")
        sys.exit(1)

    choices = [
        {"name": p["name"], "value": p}
        for p in permissions
    ]

    selected = inquirer.select(
        message="Select role:",
        choices=choices,
    ).execute()

    return selected


def prompt_duration(max_duration: int) -> int:
    """Prompt for duration with validation."""
    try:
        from InquirerPy import inquirer
    except ImportError:
        while True:
            val = input(f"Duration (hours) [1-{max_duration}, default 1]: ").strip() or "1"
            try:
                d = int(val)
                if 1 <= d <= max_duration:
                    return d
            except ValueError:
                pass
            print(f"Enter a number between 1 and {max_duration}")

    result = inquirer.number(
        message=f"Duration (hours) [1-{max_duration}]:",
        default=1,
        min_allowed=1,
        max_allowed=max_duration,
    ).execute()

    return int(result)


def prompt_justification_and_ticket(account_name: str, prev_justification: str | None = None, prev_ticket: str | None = None) -> tuple[str, str]:
    """Prompt for justification and ticket, with option to reuse previous values."""
    try:
        from InquirerPy import inquirer
    except ImportError:
        return _prompt_justification_and_ticket_basic(account_name, prev_justification, prev_ticket)

    if prev_justification is not None:
        reuse = inquirer.confirm(
            message=f"Use same justification/ticket for {account_name}?",
            default=True,
        ).execute()
        if reuse:
            return prev_justification, prev_ticket or ""

    justification = inquirer.text(
        message=f"Justification for {account_name}:",
        validate=lambda x: len(x.strip()) > 0,
        invalid_message="Justification is required",
    ).execute()

    ticket = inquirer.text(
        message=f"Ticket for {account_name}:",
    ).execute()

    return justification.strip(), ticket.strip()


def _prompt_justification_and_ticket_basic(account_name: str, prev_j: str | None, prev_t: str | None) -> tuple[str, str]:
    """Fallback prompts without InquirerPy."""
    if prev_j is not None:
        reuse = input(f"Use same justification/ticket for {account_name}? [Y/n]: ").strip().lower()
        if reuse != "n":
            return prev_j, prev_t or ""

    while True:
        justification = input(f"Justification for {account_name}: ").strip()
        if justification:
            break
        print("Justification is required")

    ticket = input(f"Ticket for {account_name}: ").strip()
    return justification, ticket


def format_request_table(requests_list: list[dict]) -> str:
    """Format requests as a readable table."""
    if not requests_list:
        return "No requests found."

    # Status icons
    status_icon = {
        "pending": "⏳",
        "approved": "✅",
        "rejected": "❌",
        "revoked": "🔄",
        "cancelled": "🚫",
        "in progress": "⏩",
        "scheduled": "📅",
        "ended": "⏹",
        "expired": "💤",
    }

    lines = []
    lines.append(f"{'ID':<38} {'Account':<22} {'Role':<30} {'Duration':>4}h  {'Status':<12} {'Created'}")
    lines.append("─" * 130)

    for r in sorted(requests_list, key=lambda x: x.get("createdAt", ""), reverse=True):
        rid = r.get("id", "")[:36]
        account = r.get("accountName", "")[:20]
        role = r.get("role", "")[:28]
        duration = r.get("duration", "")
        status = r.get("status", "unknown")
        icon = status_icon.get(status.lower(), "?")
        created = r.get("createdAt", "")[:19]

        lines.append(f"{rid:<38} {account:<22} {role:<30} {str(duration):>4}h  {icon} {status:<10} {created}")

    return "\n".join(lines)


def format_request_detail(r: dict) -> str:
    """Format a single request as detailed view."""
    status_icon = {
        "pending": "⏳", "approved": "✅", "rejected": "❌",
        "revoked": "🔄", "cancelled": "🚫", "in progress": "⏩",
        "scheduled": "📅", "ended": "⏹", "expired": "💤",
    }
    status = r.get("status", "unknown")
    icon = status_icon.get(status.lower(), "?")

    lines = [
        f"Request: {r.get('id', '')}",
        f"Status:  {icon} {status}",
        f"Account: {r.get('accountName', '')} ({r.get('accountId', '')})",
        f"Role:    {r.get('role', '')}",
        f"Duration: {r.get('duration', '')}h",
        f"Start:   {r.get('startTime', '')}",
        f"End:     {r.get('endTime', 'N/A')}",
        f"Justification: {r.get('justification', '')}",
        f"Ticket:  {r.get('ticketNo', 'N/A')}",
        f"Requester: {r.get('email', '')}",
    ]

    if r.get("approver"):
        lines.append(f"Approver: {r.get('approver', '')}")
    if r.get("comment"):
        lines.append(f"Comment: {r.get('comment', '')}")
    if r.get("revoker"):
        lines.append(f"Revoker: {r.get('revoker', '')}")
    if r.get("revokeComment"):
        lines.append(f"Revoke reason: {r.get('revokeComment', '')}")

    lines.append(f"Created: {r.get('createdAt', '')}")
    lines.append(f"Updated: {r.get('updatedAt', '')}")

    return "\n".join(lines)
