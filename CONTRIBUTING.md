# Contributing

## Keep the repo generic

This repo is meant to be shareable. Real organisation detail lives only in the
untracked `config.yaml` / `secrets.yaml` on the server; everything committed --
code, comments, docs, examples, tests, samples -- uses placeholders.

**Never commit**

- `config.yaml`, `secrets.yaml`, `bld.txt`, or anything under `reports/`, `backups/`, `logs/` (all gitignored -- keep it that way)
- Internal AD domains, OU or group names, site codes, internal hostnames or IP addresses
- Real account names, email addresses, hostnames, or counts/figures taken from production data
- API keys, passwords, tenant/organisation IDs

**Use instead**

| For | Placeholder |
|---|---|
| Sites | `SITE-A`, `SITE-B`, `SITE-C` |
| Public mail / web domains | `example.org.au`, `site-a.example.org.au` |
| Internal AD domains | `corp.example.org`, `shared.example.local` |
| IP addresses | the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Test-data organisations (`tests/`) | made-up names on `.test` domains (Riverside Health, `riversidehealth.test`) |
| Credentials in examples | `YOUR_..._KEY`, `CHANGE_ME` |

When a comment explains a bug found on real data, describe it generically:
"thousands of one site's accounts landed in another", not the site names and the count.

The public organisation name and the vendors/tools in use are public knowledge and fine to mention.

## The pre-commit check

`.githooks/pre-commit` runs `tools/check_identifiers.py` on every commit. It
builds its denylist from your local `config.yaml` and `secrets.yaml` (site
codes, domains, OUs, host groups, the publish server, the Hadrian org id, every
secret value) plus an optional untracked `.identifiers.local` (one term or
regex per line), so the list itself is never committed. It blocks the commit
and names the matched term -- never the secret values.

Enable it once per clone:

```bash
git config core.hooksPath .githooks
python3 -m venv venv && venv/bin/pip install -r requirements.txt   # the check needs PyYAML
```

- `tools/check_identifiers.py --all` scans every tracked file (run it after changing the config or the rules).
- A genuine false positive: put `identifier-check: ok` on the line, or add a generic regex to `.identifiers-allow` (committed -- describe the pattern, never the real value).
- A clone without a `config.yaml` has nothing to check against and passes.

## Tests

`tests/run_e2e.py` runs every collector against mocked vendor APIs into a throwaway database, then the rollups, reports, action packs and every dashboard query. Run it before committing anything that touches collectors, rollups or reports; `SAMPLES_DIR=reports` also refreshes the committed synthetic samples.
