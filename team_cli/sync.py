"""AWS config profile sync logic."""
import configparser
import os
import re


AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")
SSO_REGISTRATION_SCOPES = "sso:account:access"


def _read_aws_config() -> configparser.ConfigParser:
    """Read ~/.aws/config, preserving existing content."""
    config = configparser.ConfigParser()
    if os.path.exists(AWS_CONFIG_PATH):
        config.read(AWS_CONFIG_PATH)
    return config


def _write_aws_config(config: configparser.ConfigParser):
    """Write config back to ~/.aws/config."""
    os.makedirs(os.path.dirname(AWS_CONFIG_PATH), exist_ok=True)
    with open(AWS_CONFIG_PATH, "w") as f:
        config.write(f)


def _get_existing_account_ids(config: configparser.ConfigParser) -> set[str]:
    """Extract all sso_account_id values from existing profiles."""
    ids = set()
    for section in config.sections():
        if config.has_option(section, "sso_account_id"):
            ids.add(config.get(section, "sso_account_id"))
    return ids


def _sanitize_profile_name(account_name: str) -> str:
    """Convert account name to a valid profile name."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", account_name.lower().replace(" ", ""))


def _ensure_sso_session(config: configparser.ConfigParser, sync_config: dict) -> bool:
    """Ensure sso-session block exists. Returns True if added."""
    session_name = sync_config["sso_session_name"]
    section = f"sso-session {session_name}"
    if config.has_section(section):
        return False
    config.add_section(section)
    config.set(section, "sso_start_url", sync_config["sso_start_url"])
    config.set(section, "sso_region", sync_config["sso_region"])
    config.set(section, "sso_registration_scopes", SSO_REGISTRATION_SCOPES)
    return True


def sync_profiles(policy: list[dict], sync_config: dict) -> list[dict]:
    """Sync eligible accounts to ~/.aws/config based on policy and config.

    Args:
        policy: Full policy list from getUserPolicy (each entry has accounts + permissions).
        sync_config: The [sync] section from config.toml.

    Returns:
        List of actions taken: [{"account": name, "id": id, "action": str, "profiles": [...]}]
    """
    profile_map = sync_config.get("profile_map", {})
    account_overrides = sync_config.get("account_overrides", {})
    default_region = sync_config.get("default_region", "us-east-1")
    session_name = sync_config["sso_session_name"]

    # Build per-account permission set map from policy
    account_info = {}
    for entry in policy:
        perm_names = [p["name"] for p in entry.get("permissions", [])]
        for acct in entry.get("accounts", []):
            aid = acct["id"]
            if aid not in account_info:
                account_info[aid] = {
                    "name": acct["name"],
                    "id": aid,
                    "permissions": set(),
                }
            account_info[aid]["permissions"].update(perm_names)

    aws_config = _read_aws_config()
    existing_ids = _get_existing_account_ids(aws_config)
    _ensure_sso_session(aws_config, sync_config)

    results = []

    for aid, info in sorted(account_info.items(), key=lambda x: x[1]["name"]):
        account_name = info["name"]
        account_id = info["id"]
        profile_base = _sanitize_profile_name(account_name)

        if account_id in existing_ids:
            results.append({
                "account": account_name,
                "id": account_id,
                "action": "exists",
                "profiles": [],
            })
            continue

        overrides = account_overrides.get(account_name, {})
        region = overrides.get("region", default_region)

        added_profiles = []

        for perm_name in sorted(info["permissions"]):
            if perm_name not in profile_map:
                continue
            suffix = profile_map[perm_name]
            profile_name = f"{profile_base}{suffix}"
            section = f"profile {profile_name}"
            if not aws_config.has_section(section):
                aws_config.add_section(section)
                aws_config.set(section, "sso_session", session_name)
                aws_config.set(section, "sso_account_id", account_id)
                aws_config.set(section, "sso_role_name", perm_name)
                aws_config.set(section, "region", region)
                added_profiles.append(profile_name)

        results.append({
            "account": account_name,
            "id": account_id,
            "action": "added" if added_profiles else "skipped",
            "profiles": added_profiles,
        })

    if any(r["action"] == "added" for r in results):
        _write_aws_config(aws_config)

    return results
