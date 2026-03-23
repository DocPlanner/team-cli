# team-cli

A command-line interface for [AWS TEAM](https://aws.amazon.com/solutions/implementations/temporary-elevated-access-management/) (Temporary Elevated Access Management). Request, approve, and audit temporary elevated access to AWS accounts — without leaving the terminal.

## Features

- **Browser-based login** via Cognito Hosted UI (OAuth2 + PKCE) with automatic token refresh
- **Interactive and scriptable** — use interactive prompts or pass flags for CI/automation
- **Multi-account requests** — select multiple accounts and submit requests in one go
- **AWS config sync** — auto-generate `~/.aws/config` SSO profiles from your TEAM-eligible accounts
- **Audit** — query elevation requests with optional CloudTrail event correlation, with JSON output for piping

## Requirements

- Python 3.11+
- A deployed [AWS TEAM](https://aws.amazon.com/solutions/implementations/temporary-elevated-access-management/) instance (AppSync API, Cognito user pool)

## Installation

```bash
pip install .
```

Or install in editable/development mode:

```bash
pip install -e .
```

This makes the `team` command available in your shell.

### Dependencies

Installed automatically:

| Package | Purpose |
|---|---|
| `requests` | HTTP client for Cognito and AppSync APIs |
| `InquirerPy` | Interactive prompts (account/role selection, multi-select) |

## Configuration

Run the interactive setup wizard:

```bash
team configure
```

You'll be prompted for your TEAM deployment values:

| Setting | Source |
|---|---|
| AppSync endpoint URL | Your TEAM CloudFormation stack outputs |
| Cognito domain | Cognito user pool → App integration → Domain name |
| Cognito client ID | Cognito user pool → App integration → App clients |
| Cognito user pool ID | Cognito user pool → General settings |
| Identity provider | Usually `IDC` (AWS Identity Center) |
| AWS region | The region your TEAM instance is deployed in |

Configuration is stored at `~/.config/team-cli/config.toml` with restrictive permissions (`600`). See [`config.example.toml`](config.example.toml) for the full format.

### View or edit config

```bash
team configure --show    # print current config
team configure --edit    # open in $EDITOR
```

## Usage

### Authentication

```bash
team login               # opens browser for Cognito/IDC login
team logout              # clears cached tokens
```

Tokens are cached locally and refreshed automatically. If a session expires mid-command, you'll be prompted to re-authenticate.

### List eligible accounts and roles

```bash
team accounts            # show accounts you can request access to
team roles               # show available permission sets
```

### Request elevated access

**Interactive mode** — multi-select accounts, pick a role, enter justification:

```bash
team request
```

**Flag mode** — for scripting or quick one-offs:

```bash
team request --account my-account --role ReadOnly --duration 2 --justification "Deploy hotfix" --ticket JIRA-123
```

| Flag | Description |
|---|---|
| `--account`, `-a` | Account name or ID (partial match supported) |
| `--role`, `-r` | Permission set name or ID |
| `--duration`, `-d` | Duration in hours (default: 1) |
| `--justification`, `-j` | Business justification (required) |
| `--ticket`, `-t` | Ticket number |
| `--start`, `-s` | Start time in ISO format (default: now) |

In interactive mode, you can select multiple accounts and reuse the same justification across them.

### Check request status

```bash
team requests            # list all your requests
team status <request-id> # detailed view of a single request
```

### Approve requests

```bash
team approve <request-id>
team approve <request-id> --comment "Looks good"
```

### Audit elevation requests

Query elevation history with optional CloudTrail event correlation. At least one filter is required.

```bash
team audit --actor user@example.com
team audit --account 123456789012 --from 2025-01-01 --to 2025-01-31
team audit --role AdministratorAccess --json
team audit --actor user@example.com --no-logs   # skip CloudTrail fetching
```

| Flag | Description |
|---|---|
| `--actor` | Filter by requester email |
| `--account` | Filter by AWS account ID or name |
| `--role` | Filter by permission set name |
| `--from` | Start date (`YYYY-MM-DD`) |
| `--to` | End date (`YYYY-MM-DD`) |
| `--status` | Request status filter (default: `ended`) |
| `--json` | JSON output (auto-enabled when piped) |
| `--no-logs` | Skip CloudTrail event fetching |
| `--limit` | Max requests to process (default: 100) |

JSON output is automatically enabled when stdout is not a TTY, making it easy to pipe into `jq` or other tools.

### Sync AWS CLI profiles

Automatically generate `~/.aws/config` SSO profiles for your TEAM-eligible accounts:

```bash
team sync
```

This requires SSO sync settings in your config. Run `team configure` and answer "yes" to the SSO sync prompt, or add a `[sync]` section to your config file:

```toml
[sync]
sso_session_name = "my-org"
sso_start_url = "https://my-org.awsapps.com/start"
sso_region = "us-east-1"
default_region = "us-east-1"

# Map TEAM permission set names to profile name suffixes
# Only listed permission sets generate profiles
[sync.profile_map]
ReadOnly = ""                    # my-account
AdministratorAccess = "-admin"   # my-account-admin
```

Accounts already present in `~/.aws/config` (matched by `sso_account_id`) are skipped.

## How it works

1. **Authentication** — `team login` runs an OAuth2 Authorization Code flow with PKCE. A local HTTP server on port 8484 captures the callback. Tokens (ID, access, refresh) are cached at `~/.config/team-cli/tokens.json` with `600` permissions.

2. **API** — All TEAM operations go through the AppSync GraphQL API, authenticated with the Cognito ID token. Queries auto-paginate where applicable.

3. **Sync** — `team sync` reads your TEAM-eligible accounts and permissions, then writes matching SSO profiles into `~/.aws/config`. It creates an `sso-session` block if missing and only adds profiles for permission sets listed in your `profile_map`.

## License

MIT
