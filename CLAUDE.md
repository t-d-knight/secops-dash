# Notes for Claude

- Keep the repo generic: follow CONTRIBUTING.md ("Keep the repo generic"). No internal domains, OUs, site codes, IPs, account names or production figures in code, comments, docs, examples or tests -- use the placeholders listed there. Real values belong only in the untracked config.yaml / secrets.yaml.
- Before committing, run `venv/bin/python3 tools/check_identifiers.py` (the pre-commit hook does this; `--all` for the whole tree) and `tests/run_e2e.py` for anything touching collectors, rollups or reports.
- Never print secrets.yaml or config.yaml contents to the terminal; read the specific key you need.
- The live install runs from cron (crontab.example). Everything after the 02:00 collection waits on logs/.collector.lock; don't schedule anything heavy before it -- the collector skips the night if the lock is held.
- Schema changes go in db_schema.py as idempotent statements placed after the CREATE TABLE they depend on (a fresh database must build cleanly -- the e2e suite checks this).
