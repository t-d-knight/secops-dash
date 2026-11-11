# Rules for AI coding agents

These rules apply to any AI assistant working in this repo (Claude Code, Copilot, Codex, Cursor, …). People
should follow them too. [CONTRIBUTING.md](CONTRIBUTING.md) has the full detail; this file collects what an
agent has to get right and links out for the rest.

## Starting out: brief to hand on

Paste this to a new person or agent before their first session:

> You're working on secops-dash, a security reporting pipeline (vendor APIs → PostgreSQL → Grafana,
> PDF reports and action packs). Before changing anything:
> 1. Read `AGENTS.md` (rules), `CONTRIBUTING.md` (keeping the repo generic, writing reports) and
>    `robots_fighting.md` (who's working on what, recent log).
> 2. `git fetch origin` and start from current `main`.
> 3. Claim the area you'll touch in `robots_fighting.md`. Ask before touching the live install.
> 4. Never commit real organisation detail, and never print `config.yaml` / `secrets.yaml`.
> 5. Before committing, run `tools/check_identifiers.py`, plus `tests/run_e2e.py` for code changes.
> 6. Finish with a log entry: what's local, pushed or deployed, what you verified and what you didn't.
>    Release your claim.
>
> If something isn't covered, follow how the existing code does it and note the question in the log.

## Coordinate first

More than one person or agent may be working here at once. Before you start, read
[robots_fighting.md](robots_fighting.md):
- Claim the area you're editing, or the live install before deploying, and release the claim when done.
- Don't change an area someone else has claimed. Record the conflict in the log instead.
- Add a log entry stating honestly what is local, pushed or deployed, what you verified and what you didn't.
- If you disagree with someone else's change, write it in the log. Don't silently revert it.

## What this repo is

Collectors pull security data from vendor APIs, map every record to a site and store it in PostgreSQL. Rollups,
Grafana dashboards, PDF reports and action packs are built from that data. The code is meant to be shareable;
the real organisation's details exist only in untracked files on the server that runs it.

## Hard rules

1. **Keep the repo generic.** Never write internal domains, OU or group names, site codes, internal
   hostnames or IPs, account names, email addresses, tenant/org IDs or figures from production data into
   anything tracked: code, comments, docs, tests, samples, commit messages or PR text. Use the placeholders
   in [CONTRIBUTING.md](CONTRIBUTING.md#keep-the-repo-generic). This applies even when the user has pasted
   real values into the conversation: use them to understand the problem, then write placeholders.
2. **Never print secrets.** Don't `cat`, `grep` or echo `secrets.yaml` or `config.yaml`. Read only the key you
   need, and never repeat a secret value in output, logs or files.
3. **Never commit untracked operational files**: `config.yaml`, `secrets.yaml`, `bld.txt`, `*.local.md`,
   `.identifiers.local`, or anything under `reports/`, `backups/`, `logs/`. Don't weaken `.gitignore` or the
   pre-commit hook to get a commit through.
4. **Read from vendor APIs, never change them.** Collectors use read-only scopes. Don't add calls that change
   vendor state (containing hosts, closing or assigning alerts, suppressing findings, disabling accounts),
   even if the scope would allow it.
5. **Don't rewrite shared history.** No force-push, no history rewrites, no deleting branches unless the
   user does it themselves.
6. **Don't touch the live install unless asked.** Deploying, running collectors, editing the server's
   config or crontab, and pushing Grafana dashboards all affect real reports. Get an explicit go-ahead
   for each one.

## Before every commit

- `git fetch origin` first. If `main` has moved, integrate it and rerun the checks
  (see [robots_fighting.md](robots_fighting.md#before-you-push)).
- `venv/bin/python3 tools/check_identifiers.py` (the pre-commit hook runs it; `--all` scans the whole tree).
  If it flags a line, rewrite the line. Don't add an allow rule unless it's a genuine false positive.
- `tests/run_e2e.py` for anything touching collectors, rollups, reports or dashboard queries. If sample
  reports change, regenerate them with `tests/demo_samples.py` (made-up estate only).
- Schema changes go in `db_schema.py` as idempotent statements after the `CREATE TABLE` they depend on.
  A fresh database must build cleanly.

## Working with the live install

- The nightly run is driven by cron (`crontab.example`). Everything after the 01:00 collection waits on
  `logs/.collector.lock`. Don't schedule heavy work before it, because the collector skips the night if
  the lock is held.
- Claim the Live install row in [robots_fighting.md](robots_fighting.md) before deploying, and log
  the commit you deployed. If the server has changes that aren't in git, stop and record them.
- Deploy only changed files, after diffing the server copy against the local one. Keep a dated `.bak`
  copy of anything replaced (`deploy.sh` and weekly maintenance handle the pattern).
- Treat what the user pastes from vendor consoles, logs or the server as ground truth over your own
  assumptions about field names or API behaviour. Say when something is unverified, and probe with a
  read-only call before building on a guess.

## Reports and dashboards

Follow [CONTRIBUTING.md → Writing reports](CONTRIBUTING.md#writing-reports). In short:
- Lead with what changed and what needs deciding.
- Keep risk apart from raw volume, and don't count coverage growth as new vulnerabilities.
- Show opened next to fixed, and remember that findings aren't effort.
- Generated text states facts. Asks and decisions come from a person, never from code.
- Personal data (names, PCs, USB activity) follows the audience rules in the
  [ops guide](knowledge-base/ops-guide.md#access-and-data-handling). Region reports mask people.

## Local notes

A `NEXT-STEPS.local.md` (untracked, excluded via `.git/info/exclude`) may exist with the current plan
and real-world context. Read it when resuming work. It can hold real names, so nothing from it goes into
tracked files.
