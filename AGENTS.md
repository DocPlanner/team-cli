# AGENTS.md — team-cli

## Project

CLI for AWS TEAM (Temporary Elevated Access Management). Python 3.11+, distributed via Homebrew.

## Open-source readiness

This repo will be open-sourced. All contributions must follow these rules:

### Never include in code, comments, commits, or docs

- AWS account IDs, ARNs, or resource identifiers
- Cognito domain URLs, client IDs, user pool IDs
- AppSync endpoint URLs
- Internal domain names (*.docplanner.*, *.awsapps.com, etc.)
- Employee names, emails, or usernames
- Internal ticket IDs, Slack channels, or Jira project keys
- IP addresses, VPN endpoints, or internal URLs
- SSO start URLs or session names
- Any value from `config.example.toml` that contains real deployment data

### Safe to include

- Generic examples using placeholder values (`example.com`, `123456789012`, `my-org`)
- Architecture descriptions that don't reference specific infrastructure

## Contributing

### Structure

```
team_cli/
  cli.py          — argparse entry point, command handlers
  api.py          — GraphQL AppSync client
  auth.py         — OAuth2 + PKCE authentication
  config.py       — config and token management
  audit.py        — audit query and CloudTrail correlation
  interactive.py  — InquirerPy prompts (fuzzy search)
  queries.py      — GraphQL query definitions
  sync.py         — AWS config profile sync
Formula/
  team-cli.rb     — Homebrew formula
completions/
  team.bash       — bash completions
```

### Commands

All commands follow the pattern `cmd_<name>(args)` in `cli.py`, dispatched via a `COMMANDS` dict.

Interactive prompts use `inquirer.fuzzy` for searchable selection. All pickers fall back to numbered menus when InquirerPy is unavailable.

### Releasing

1. Bump version in `pyproject.toml`, `team_cli/__init__.py`, and `Formula/team-cli.rb` (tag + version lines)
2. Update `charset-normalizer` or other resources in the Formula if dependencies changed
3. Commit to main
4. Tag: `git tag v0.3.0 && git push --tags`
5. The GitHub Actions workflow creates a release automatically
6. Users update via `brew update && brew upgrade team-cli`

### Formula resources

When updating Python dependencies in the Formula, use sdist tarballs from PyPI. Pin `charset-normalizer` to 3.3.2 (3.4.x requires `mypy` as a build dependency which fails in Homebrew's `--no-binary :all:` environment).

### Testing

Run `team --help` after changes to verify the CLI loads. All commands should work both interactively (prompts) and non-interactively (flags).
