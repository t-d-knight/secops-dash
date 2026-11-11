# Contributing

Using an AI coding agent? It must follow [AGENTS.md](AGENTS.md) too (CLAUDE.md imports it).
Before you start, and before you push or deploy, check [robots_fighting.md](robots_fighting.md) to see
who's working on what, claim your area, and add a log entry.

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

## Writing reports

The reports are read by people who won't open a security console. Each report should answer, in this order:
what changed, what it means, whether remediation is keeping up, and what needs a decision. A list of
what currently exists comes last.

- **Separate risk from volume.** Never use a raw vulnerability count as a headline on its own. Show it next to
  the counts that measure risk: known exploited (KEV), remotely exploitable, internet-facing, overdue against SLA.
  A growing CVE population isn't the same as growing risk.
- **Don't count coverage growth as new vulnerabilities.** Findings on newly assessed hosts and bulk loads
  (`reporting.vuln_bulk_load_dates`) stay out of "opened". More visibility should never look like a worse result.
- **Show incoming work next to completed work.** Wherever "fixed" appears, show "opened" for the same period,
  plus the net movement, and the trend over several periods where history allows. One period's result is a
  data point, not a trend.
- **Remember that findings aren't effort.** One reboot can close a thousand findings, and one browser release
  can open a thousand. When a report argues about workload or capacity, count in units of work (hosts patched,
  fixes applied, campaigns finished) as well as findings, and say which unit a figure uses.
- **Generated text states facts; people write decisions.** Code can write sentences like "opened exceeded
  fixed for the fourth week running". Asks, decisions and judgements come from a person (an untracked input
  file, not hard-coded text), so a report never shows an ask nobody made.
- **Keep the wording neutral and checkable.** Use neutral arrows, state the period and denominator, and only
  use words the data supports ("compromise indicators", not "signs of compromise"). Caveats go in the
  footer, stated once.
- **Keep outcomes separate.** Accepted risk is not remediation: never count it as "resolved" alongside fixed
  items. "Done" means closure backed by evidence (a closed date plus a ticket, or the finding gone from the
  data), not just a status change. Coverage gaps (no sensor, unsupported OS) are visibility and lifecycle
  problems, so word them that way, not as confirmed vulnerability risk.
- **Show the base.** Every percentage carries its denominator (n/N, or "42 fixes"), and a change on a small
  base says so. "Small base" and "material movement" are thresholds too, so they follow the next rule.
- **Prompt, don't judge.** Without agreed targets, the report shows direction and asks questions ("validate
  the decline in high-severity SLA performance"). It doesn't hand out Improving/Worsening verdicts or RAG
  colours.
- **Label every number.** Any threshold or target you add (SLA days, "patched within 35 days", grace periods,
  patch-tier offsets) is either **policy** (record who set it) or **assumed** (record why). Note it in
  `config.yaml.example` or the ops guide's "Reading the numbers" section, so nobody mistakes a default for
  a rule.
- **Show before and after.** If a change moves report numbers, run `tests/demo_samples.py` before and after
  on the same day and record what changed in [robots_fighting.md](robots_fighting.md).
- **Keep each product focused.** The monthly scorecard's nine measures cover posture. New kinds of measure
  (e.g. workload or sustainability) get their own page or scorecard, not extra rows on the existing one.

## Tests

`tests/run_e2e.py` runs every collector against mocked vendor APIs into a throwaway database, then the rollups, reports, action packs and every dashboard query. Run it before committing anything that touches collectors, rollups or reports. `tests/demo_samples.py` regenerates the committed sample reports (`reports/sample-*`) from a made-up four-site estate with months of history, built on the same mocks.
