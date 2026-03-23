"""Deployment config and token storage."""
import json
import os
import sys
import time
import tomllib

CONFIG_DIR = os.path.expanduser("~/.config/team-cli")
TOKEN_FILE = os.path.join(CONFIG_DIR, "tokens.json")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.toml")

COGNITO_REDIRECT_URI = "http://localhost:8484/callback"
CALLBACK_PORT = 8484


def ensure_config_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)


def save_tokens(tokens: dict):
    """Save tokens with timestamp."""
    ensure_config_dir()
    tokens["saved_at"] = time.time()
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f)
    os.chmod(TOKEN_FILE, 0o600)


def load_tokens() -> dict | None:
    """Load cached tokens, or None if missing/expired."""
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE) as f:
        tokens = json.load(f)
    return tokens


def clear_tokens():
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)


def load_config() -> dict | None:
    """Read config.toml and return as dict, or None if missing."""
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "rb") as f:
        return tomllib.load(f)


def _format_toml_value(value) -> str:
    """Format a Python value as a TOML value string."""
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        items = ", ".join(_format_toml_value(v) for v in value)
        return f"[{items}]"
    raise ValueError(f"Unsupported TOML value type: {type(value)}")


def _write_toml_table(lines: list[str], data: dict, prefix: str = ""):
    """Recursively write TOML tables to lines list."""
    for key, value in data.items():
        if not isinstance(value, dict):
            lines.append(f"{key} = {_format_toml_value(value)}")
    for key, value in data.items():
        if isinstance(value, dict):
            section = f"{prefix}.{key}" if prefix else key
            has_simple = any(not isinstance(v, dict) for v in value.values())
            if has_simple:
                lines.append(f"\n[{section}]")
                _write_toml_table(lines, value, section)
            else:
                for sub_key, sub_value in value.items():
                    sub_section = f"{section}.{sub_key}"
                    lines.append(f"\n[{sub_section}]")
                    _write_toml_table(lines, sub_value, sub_section)


def save_config(data: dict):
    """Write config dict to config.toml."""
    ensure_config_dir()
    lines = ["# TEAM CLI configuration \u2014 run `team configure` to regenerate"]
    _write_toml_table(lines, data)
    lines.append("")

    with open(CONFIG_FILE, "w") as f:
        f.write("\n".join(lines))
    os.chmod(CONFIG_FILE, 0o600)


def get_config() -> dict:
    """Load and validate config. Raises SystemExit with helpful message if missing."""
    config = load_config()
    if config is None:
        print(
            "Not configured. Run `team configure` to set up your TEAM CLI deployment values.",
            file=sys.stderr,
        )
        sys.exit(1)

    required = [
        ("cognito", "domain"),
        ("cognito", "client_id"),
        ("cognito", "user_pool_id"),
        ("appsync", "endpoint"),
        ("aws", "region"),
    ]
    missing = []
    for section, key in required:
        if section not in config or key not in config[section]:
            missing.append(f"{section}.{key}")
    if missing:
        print(
            f"Incomplete configuration. Missing: {', '.join(missing)}\n"
            "Run `team configure` to fix.",
            file=sys.stderr,
        )
        sys.exit(1)

    return config
