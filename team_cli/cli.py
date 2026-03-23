"""Argument parsing and command dispatch."""
import argparse
import os
import sys
from datetime import datetime, timezone

from team_cli.auth import require_auth, get_user_info, login as auth_login, get_valid_tokens, clear_tokens
from team_cli.api import (
    get_user_policy, get_requests_by_email, get_request,
    create_request, update_request, validate_request, get_settings,
    AuthExpiredError,
)
from team_cli.config import CONFIG_FILE, load_config, save_config, get_config
from team_cli.interactive import (
    with_spinner, select_accounts, select_role,
    prompt_duration, prompt_justification_and_ticket,
    format_request_table, format_request_detail,
)
from team_cli.sync import sync_profiles
from team_cli.audit import fetch_audit_data, format_audit_json, format_audit_table


def _ensure_tokens():
    """Get valid tokens, handling auth errors gracefully."""
    try:
        return require_auth()
    except AuthExpiredError:
        clear_tokens()
        print("Session expired. Logging in again...")
        return auth_login()
    except Exception as e:
        print(f"Authentication error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_login(args):
    """team login — authenticate via browser."""
    tokens = auth_login()
    user = get_user_info(tokens)
    print(f"Logged in as {user['email']}")
    if user["group_ids"]:
        print(f"Groups: {', '.join(user['group_ids'][:5])}")


def cmd_logout(args):
    """team logout — clear cached tokens."""
    clear_tokens()
    print("Logged out. Cached tokens cleared.")


def cmd_accounts(args):
    """team accounts — list eligible accounts."""
    tokens = _ensure_tokens()

    use_json = args.json or not sys.stdout.isatty()

    with with_spinner("Fetching eligible accounts..."):
        policy = get_user_policy(tokens)

    if not policy or not policy.get("policy"):
        if use_json:
            print("[]")
        else:
            print("No eligible accounts found.")
        return

    # Collect accounts with their permissions
    account_map = {}
    for entry in policy["policy"]:
        perm_list = [{"name": p["name"], "id": p["id"]} for p in entry.get("permissions", [])]
        for acct in entry.get("accounts", []):
            aid = acct["id"]
            if aid not in account_map:
                account_map[aid] = {
                    "name": acct["name"],
                    "id": aid,
                    "permissions": {},
                }
            for p in perm_list:
                account_map[aid]["permissions"][p["id"]] = p

    accounts = sorted(account_map.values(), key=lambda a: a["name"])

    if use_json:
        import json as json_mod
        output = [
            {"name": a["name"], "id": a["id"], "permissions": list(a["permissions"].values())}
            for a in accounts
        ]
        print(json_mod.dumps(output, indent=2))
    else:
        print(f"{'Account':<30} {'ID'}")
        print("─" * 50)
        for a in accounts:
            print(f"{a['name']:<30} {a['id']}")
        print(f"\n{len(accounts)} eligible accounts")


def cmd_roles(args):
    """team roles — list available permission sets."""
    tokens = _ensure_tokens()

    with with_spinner("Fetching permissions..."):
        policy = get_user_policy(tokens)

    if not policy or not policy.get("policy"):
        print("No permissions found.")
        return

    seen = set()
    permissions = []
    for entry in policy["policy"]:
        for perm in entry.get("permissions", []):
            if perm["id"] not in seen:
                seen.add(perm["id"])
                permissions.append(perm)

    permissions.sort(key=lambda p: p["name"])
    print(f"{'Permission Set':<40} {'ID'}")
    print("─" * 80)
    for p in permissions:
        print(f"{p['name']:<40} {p['id']}")


def cmd_request(args):
    """team request — create elevation request (interactive or flags)."""
    tokens = _ensure_tokens()
    user = get_user_info(tokens)

    # Fetch policy for accounts/permissions
    with with_spinner("Fetching eligible accounts..."):
        policy_data = get_user_policy(tokens)
        settings = get_settings(tokens)

    if not policy_data or not policy_data.get("policy"):
        print("No eligible accounts found. Check your TEAM eligibility.", file=sys.stderr)
        sys.exit(1)

    policy = policy_data["policy"]
    max_duration = int(settings.get("duration", 9)) if settings else 9

    # Build flat lists
    all_accounts = {}
    for entry in policy:
        for acct in entry.get("accounts", []):
            all_accounts[acct["id"]] = acct

    # Determine if interactive or flag mode
    if args.account:
        # Flag mode: single request
        _request_flag_mode(args, tokens, user, policy, all_accounts, max_duration)
    else:
        # Interactive mode: multi-select
        _request_interactive_mode(tokens, user, policy, all_accounts, max_duration, args)


def _find_account(query: str, all_accounts: dict) -> dict | None:
    """Find account by name or ID (case-insensitive partial match)."""
    query_lower = query.lower()
    # Exact ID match
    if query in all_accounts:
        return all_accounts[query]
    # Name match
    for acct in all_accounts.values():
        if acct["name"].lower() == query_lower:
            return acct
    # Partial name match
    matches = [a for a in all_accounts.values() if query_lower in a["name"].lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def _find_role(query: str, permissions: list[dict]) -> dict | None:
    """Find role by name or ID."""
    query_lower = query.lower()
    for p in permissions:
        if p["id"] == query or p["name"].lower() == query_lower:
            return p
    matches = [p for p in permissions if query_lower in p["name"].lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def _get_permissions_for_account(account_id: str, policy: list[dict]) -> list[dict]:
    """Get available permissions for a specific account from policy."""
    perms = {}
    for entry in policy:
        for acct in entry.get("accounts", []):
            if acct["id"] == account_id:
                for p in entry.get("permissions", []):
                    perms[p["id"]] = p
    return list(perms.values())


def _request_flag_mode(args, tokens, user, policy, all_accounts, max_duration):
    """Handle request creation via CLI flags."""
    account = _find_account(args.account, all_accounts)
    if not account:
        print(f"Account not found: {args.account}", file=sys.stderr)
        print("Available accounts:", ", ".join(a["name"] for a in all_accounts.values()))
        sys.exit(1)

    perms = _get_permissions_for_account(account["id"], policy)
    if not perms:
        print(f"No permissions available for {account['name']}", file=sys.stderr)
        sys.exit(1)

    if args.role:
        role = _find_role(args.role, perms)
        if not role:
            print(f"Role not found: {args.role}", file=sys.stderr)
            print("Available roles:", ", ".join(p["name"] for p in perms))
            sys.exit(1)
    elif len(perms) == 1:
        role = perms[0]
    else:
        print("Multiple roles available. Specify --role:", file=sys.stderr)
        for p in perms:
            print(f"  {p['name']}")
        sys.exit(1)

    duration = args.duration or 1
    if duration < 1 or duration > max_duration:
        print(f"Duration must be between 1 and {max_duration}", file=sys.stderr)
        sys.exit(1)

    justification = args.justification
    if not justification:
        print("--justification is required", file=sys.stderr)
        sys.exit(1)

    ticket = args.ticket or ""
    start_time = args.start or datetime.now(timezone.utc).isoformat()

    _submit_request(tokens, user, account, role, duration, start_time, justification, ticket)


def _request_interactive_mode(tokens, user, policy, all_accounts, max_duration, args):
    """Handle interactive multi-account request flow."""
    accounts_list = sorted(all_accounts.values(), key=lambda a: a["name"])
    selected_accounts = select_accounts(accounts_list)

    if not selected_accounts:
        print("No accounts selected.")
        return

    # For now, collect all permissions across selected accounts
    all_perms = {}
    for acct in selected_accounts:
        for p in _get_permissions_for_account(acct["id"], policy):
            all_perms[p["id"]] = p

    perms_list = sorted(all_perms.values(), key=lambda p: p["name"])
    if not perms_list:
        print("No permissions available for selected accounts.")
        return

    if args.role:
        role = _find_role(args.role, perms_list)
        if not role:
            print(f"Role not found: {args.role}")
            sys.exit(1)
    else:
        role = select_role(perms_list)

    duration = args.duration or prompt_duration(max_duration)
    start_time = args.start or datetime.now(timezone.utc).isoformat()

    # Prompt for justification/ticket per account (with reuse option)
    prev_justification = args.justification
    prev_ticket = args.ticket

    print(f"\nCreating {len(selected_accounts)} request(s)...")

    for i, acct in enumerate(selected_accounts):
        if prev_justification is None:
            # First account or user wants different justification
            justification, ticket = prompt_justification_and_ticket(
                acct["name"],
                prev_justification if i > 0 else None,
                prev_ticket if i > 0 else None,
            )
        else:
            justification = prev_justification
            ticket = prev_ticket or ""
            if i == 0:
                # For first account with pre-set justification, just use it
                pass
            else:
                # Ask if they want to reuse
                justification, ticket = prompt_justification_and_ticket(
                    acct["name"], justification, ticket
                )

        # After first iteration, store for reuse prompt
        if i == 0 and prev_justification is None:
            prev_justification = justification
            prev_ticket = ticket

        _submit_request(tokens, user, acct, role, duration, start_time, justification, ticket)


def _submit_request(tokens, user, account, role, duration, start_time, justification, ticket):
    """Validate and submit a single request."""
    # Validate
    try:
        validation = validate_request(
            account["id"], role["id"], user["user_id"], user["group_ids"], tokens
        )
        if not validation.get("valid"):
            print(f"  ✗ {account['name']} → denied: {validation.get('reason', 'unknown')}")
            return
    except Exception as e:
        print(f"  ⚠ {account['name']} → validation failed: {e}")
        # Continue anyway — server-side validation will catch issues

    # Create request
    try:
        result = create_request({
            "accountId": account["id"],
            "accountName": account["name"],
            "role": role["name"],
            "roleId": role["id"],
            "duration": str(duration),
            "startTime": start_time,
            "justification": justification,
            "ticketNo": ticket,
        }, tokens)
        req_id = result.get("id", "unknown")
        status = result.get("status", "pending")
        print(f"  ✓ {account['name']} → {status} (id: {req_id})")
    except Exception as e:
        print(f"  ✗ {account['name']} → failed: {e}")


def cmd_requests(args):
    """team requests — list my requests."""
    tokens = _ensure_tokens()
    user = get_user_info(tokens)

    with with_spinner("Fetching requests..."):
        reqs = get_requests_by_email(user["email"], tokens)

    print(format_request_table(reqs))


def cmd_status(args):
    """team status — check specific request."""
    tokens = _ensure_tokens()

    with with_spinner("Fetching request..."):
        req = get_request(args.request_id, tokens)

    if not req:
        print(f"Request not found: {args.request_id}", file=sys.stderr)
        sys.exit(1)

    print(format_request_detail(req))


def cmd_approve(args):
    """team approve — approve a pending request."""
    tokens = _ensure_tokens()
    user = get_user_info(tokens)

    # Fetch request first
    with with_spinner("Fetching request..."):
        req = get_request(args.request_id, tokens)

    if not req:
        print(f"Request not found: {args.request_id}", file=sys.stderr)
        sys.exit(1)

    if req.get("status", "").lower() != "pending":
        print(f"Request is not pending (status: {req.get('status')})", file=sys.stderr)
        sys.exit(1)

    print(f"Approving request from {req.get('email', '')} for {req.get('accountName', '')} / {req.get('role', '')}")

    result = update_request({
        "id": args.request_id,
        "status": "approved",
        "approver": user["email"],
        "approverId": user["user_id"],
        "comment": args.comment or "",
    }, tokens)

    print(f"✓ Request {args.request_id} approved")


def cmd_sync(args):
    """team sync — add missing accounts to ~/.aws/config."""
    config = get_config()
    sync_config = config.get("sync")
    if not sync_config:
        print("SSO sync not configured. Run `team configure` and enable SSO sync settings.", file=sys.stderr)
        sys.exit(1)

    tokens = _ensure_tokens()

    with with_spinner("Fetching eligible accounts from TEAM..."):
        policy = get_user_policy(tokens)

    if not policy or not policy.get("policy"):
        print("No eligible accounts found.")
        return

    print("Checking ~/.aws/config...\n")

    results = sync_profiles(policy["policy"], sync_config)

    added = 0
    for r in sorted(results, key=lambda x: x["account"]):
        if r["action"] == "exists":
            print(f"  ✓ {r['account']} — already configured")
        elif r["action"] == "skipped":
            print(f"  - {r['account']} — no matching permission sets")
        else:
            for p in r["profiles"]:
                print(f"  + {r['account']} ({r['id']}) — added profile '{p}'")
            added += len(r["profiles"])

    if added:
        print(f"\nUpdated ~/.aws/config with {added} new profile(s).")
    else:
        print("\nAll accounts already configured.")


def _audit_progress(current, total, req):
    """Print progress to stderr so stdout stays clean for JSON piping."""
    email = req.get("email", "?")
    acct = req.get("accountName", "?")
    print(f"\r  Fetching {current}/{total}: {email} / {acct}...   ",
          end="", file=sys.stderr, flush=True)
    if current == total:
        print(file=sys.stderr)


def cmd_audit(args):
    """team audit — audit elevation requests with CloudTrail events."""
    tokens = _ensure_tokens()

    if not any([args.actor, args.account, args.role]):
        print("At least one filter required: --actor, --account, or --role", file=sys.stderr)
        sys.exit(1)

    use_json = args.json or not sys.stdout.isatty()

    try:
        results = fetch_audit_data(
            tokens=tokens,
            actor=args.actor,
            account=args.account,
            role=args.role,
            from_date=args.from_date,
            to_date=args.to_date,
            status=args.status or "ended",
            limit=args.limit,
            include_logs=not args.no_logs,
            on_progress=_audit_progress if not use_json else None,
        )
    except AuthExpiredError:
        clear_tokens()
        print("Session expired. Run `team login` to re-authenticate.", file=sys.stderr)
        sys.exit(1)

    if use_json:
        print(format_audit_json(results))
    else:
        print(format_audit_table(results))


def cmd_configure(args):
    """team configure — set up deployment configuration."""
    if args.show:
        config = load_config()
        if config is None:
            print("No configuration found. Run `team configure` to set up.")
            return
        with open(CONFIG_FILE) as f:
            print(f.read())
        return

    if args.edit:
        editor = os.environ.get("EDITOR", os.environ.get("VISUAL", "vi"))
        if not os.path.exists(CONFIG_FILE):
            print(f"No configuration found at {CONFIG_FILE}")
            print("Run `team configure` first to create one.")
            return
        os.execvp(editor, [editor, CONFIG_FILE])
        return

    print("\nTEAM CLI Configuration")
    print("\u2500" * 22)
    print("These values come from your TEAM deployment's AWS resources.")
    print("See your organization's docs for the correct values.\n")

    existing = load_config() or {}
    ec = existing.get("cognito", {})
    ea = existing.get("appsync", {})
    ew = existing.get("aws", {})

    def _prompt(label, default=""):
        val = input(f"{label} [{default}]: " if default else f"{label}: ").strip()
        return val or default

    def _require(label, default=""):
        val = _prompt(label, default)
        if not val:
            print(f"{label} is required.", file=sys.stderr)
            sys.exit(1)
        return val

    appsync_endpoint = _require("AppSync endpoint URL", ea.get("endpoint", ""))
    cognito_domain = _require("Cognito domain", ec.get("domain", ""))
    cognito_client_id = _require("Cognito client ID", ec.get("client_id", ""))
    cognito_user_pool_id = _require("Cognito user pool ID", ec.get("user_pool_id", ""))
    cognito_idp = _prompt("Cognito identity provider", ec.get("identity_provider", "IDC"))
    aws_region = _prompt("AWS region", ew.get("region", "eu-north-1"))

    data = {
        "cognito": {
            "domain": cognito_domain,
            "client_id": cognito_client_id,
            "user_pool_id": cognito_user_pool_id,
            "identity_provider": cognito_idp,
            "scopes": ec.get("scopes", [
                "aws.cognito.signin.user.admin", "email", "openid", "phone", "profile"
            ]),
        },
        "appsync": {"endpoint": appsync_endpoint},
        "aws": {"region": aws_region},
    }

    print("\nOptional: SSO sync settings (for `team sync` command)")
    configure_sync = input("Configure SSO sync? [y/N]: ").strip().lower()

    if configure_sync == "y":
        es = existing.get("sync", {})
        sso_session = _require("SSO session name", es.get("sso_session_name", ""))
        sso_start_url = _require("SSO start URL", es.get("sso_start_url", ""))
        sso_region = _prompt("SSO region", es.get("sso_region", aws_region))
        sync_default_region = _prompt("Default AWS region", es.get("default_region", "eu-central-1"))

        print("\nProfile mapping (permission set name=suffix, one per line, empty line to finish):")
        print("  Example: ReadOnly=  (empty suffix = daily profile)")
        print("  Example: AdministratorAccess=-bg")

        profile_map = es.get("profile_map", {})
        if profile_map:
            print(f"  Current: {', '.join(f'{k}={v!r}' for k, v in profile_map.items())}")
            keep = input("  Keep current mapping? [Y/n]: ").strip().lower()
            if keep == "n":
                profile_map = {}

        if not profile_map:
            while True:
                line = input("  ").strip()
                if not line:
                    break
                if "=" not in line:
                    print("  Format: PermissionSetName=suffix")
                    continue
                name, suffix = line.split("=", 1)
                profile_map[name.strip()] = suffix.strip()

        data["sync"] = {
            "sso_session_name": sso_session,
            "sso_start_url": sso_start_url,
            "sso_region": sso_region,
            "default_region": sync_default_region,
            "profile_map": profile_map,
        }

        if es.get("account_overrides"):
            data["sync"]["account_overrides"] = es["account_overrides"]

    elif existing.get("sync"):
        data["sync"] = existing["sync"]

    save_config(data)
    print(f"\nConfiguration saved to {CONFIG_FILE}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="team",
        description="CLI for AWS TEAM — Temporary Elevated Access Management",
    )
    sub = parser.add_subparsers(dest="command")

    # login
    sub.add_parser("login", help="Authenticate via browser (Cognito/IDC)")

    # logout
    sub.add_parser("logout", help="Clear cached tokens")

    # accounts
    accounts_parser = sub.add_parser("accounts", help="List eligible accounts")
    accounts_parser.add_argument("--json", action="store_true", help="JSON output with permissions per account")

    # roles
    sub.add_parser("roles", help="List available permission sets")

    # request
    req_parser = sub.add_parser("request", help="Create elevation request")
    req_parser.add_argument("--account", "-a", help="Account name or ID (supports partial match)")
    req_parser.add_argument("--role", "-r", help="Permission set name or ID")
    req_parser.add_argument("--duration", "-d", type=int, help="Duration in hours (default: 1)")
    req_parser.add_argument("--justification", "-j", help="Business justification")
    req_parser.add_argument("--ticket", "-t", help="Ticket number")
    req_parser.add_argument("--start", "-s", help="Start time (ISO format, default: now)")

    # requests
    sub.add_parser("requests", help="List my requests")

    # status
    status_parser = sub.add_parser("status", help="Check request status")
    status_parser.add_argument("request_id", help="Request ID")

    # approve
    approve_parser = sub.add_parser("approve", help="Approve a pending request")
    approve_parser.add_argument("request_id", help="Request ID")
    approve_parser.add_argument("--comment", "-c", help="Approval comment")

    # audit
    audit_parser = sub.add_parser("audit", help="Audit elevation requests with CloudTrail events")
    audit_parser.add_argument("--actor", help="Filter by requester email")
    audit_parser.add_argument("--account", help="Filter by AWS account ID or name")
    audit_parser.add_argument("--role", help="Filter by permission set name")
    audit_parser.add_argument("--from", dest="from_date", help="Start date (YYYY-MM-DD)")
    audit_parser.add_argument("--to", dest="to_date", help="End date (YYYY-MM-DD)")
    audit_parser.add_argument("--status", help="Request status filter (default: ended)")
    audit_parser.add_argument("--json", action="store_true", help="JSON output")
    audit_parser.add_argument("--no-logs", action="store_true", help="Skip CloudTrail event fetching")
    audit_parser.add_argument("--limit", type=int, default=100, help="Max requests to process (default: 100)")

    # sync
    sub.add_parser("sync", help="Sync eligible accounts to ~/.aws/config")

    # configure
    configure_parser = sub.add_parser("configure", help="Set up deployment configuration")
    configure_parser.add_argument("--show", action="store_true", help="Print current configuration")
    configure_parser.add_argument("--edit", action="store_true", help="Open config in $EDITOR")

    return parser


COMMANDS = {
    "login": cmd_login,
    "logout": cmd_logout,
    "accounts": cmd_accounts,
    "roles": cmd_roles,
    "request": cmd_request,
    "requests": cmd_requests,
    "status": cmd_status,
    "approve": cmd_approve,
    "audit": cmd_audit,
    "sync": cmd_sync,
    "configure": cmd_configure,
}


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handler = COMMANDS.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    try:
        handler(args)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
    except AuthExpiredError:
        clear_tokens()
        print("Session expired. Run `team login` to re-authenticate.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
