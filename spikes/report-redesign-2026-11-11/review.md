# SecOps report redesign spike — review note

Local comparison sample: [comparison.html](comparison.html). It compares the committed fictional demo reports with alternatives using the same displayed values and reporting dates.

## Review

- **Weekly executive page:** the current first page makes estate inventory the opening view; risk appears on page 2. The alternative puts known-exploited and remotely exploitable counts first, then separates current coverage and weekly finding flows. It makes snapshot date and flow period explicit. It is weaker for readers who need the full estate inventory immediately, and it still needs a human-authored ask.
- **Programme impact:** the current “Resolved” total combines “Done” with “Accepted risk”. The alternative reconciles all 10 actions while keeping accepted risk distinct. The sample has no dedicated verification field, so it cannot identify verified remediation from status alone. The “0 verified” sample label means “not explicitly identifiable here,” not zero actual remediation.
- **Monthly scorecard:** all nine measures and values/direction are preserved. The alternative labels the two fix-on-time rates as September fixes → October fixes and the other seven as 01 Oct → 29 Oct snapshots. It shows the October fixed-count denominators for the pooled rates and marks other unavailable denominators instead of inventing them. It retains direction-only wording and omits service comparisons, targets, ranking, and materiality.

## Assumptions

- Week 43 activity is 19–25 Oct 2026; the source report’s current snapshots are as at generation on 29 Oct. Trend deltas shown in the alternative retain the source’s 19 Oct baseline.
- The scorecard sample is generated for October 2026. The source code computes fix-on-time as September's pooled fix rate versus October's pooled fix rate; 1,626 critical and 5,827 high October fixes are the respective denominators. The other seven measures use snapshots on 01 Oct and 29 Oct.
- Impact outcomes follow the action log’s current status labels. “Done” is not treated as verified without a field or agreed evidence rule.

## Unresolved metric semantics

- Whether weekly executive page 1 should replace the estate page, or become a new summary ahead of it.
- Which snapshot date should anchor executive page 1: period end or generation time, when those differ.
- What evidence qualifies an action as verified remediation, and whether “Done” always means that evidence was checked.
- Whether accepted risk should be represented as an outcome category, a separate decision state, or both; who owns expiry/review dates.
- Exact numerator/denominator values for the seven snapshot measures, especially sensor coverage and the server-active population. The committed HTML does not expose them. The existing displayed 01 Oct / 29 Oct column labels also imply snapshot dates for the two fix-on-time rates even though the code compares monthly fix cohorts; the presentation should make that period difference explicit.

## Smallest candidate implementation

One page-template change to executive report page 1, sourcing only already-rendered values and preserving its existing page 2; separately, a presentation-only impact summary that splits existing action statuses without recoding them as verified. For the scorecard, add denominator/sample-size display only after its measure inputs are confirmed. No collector, rollup, schema, query, or metric-definition change is implied by these mockups.

## Status and validation

- **Status:** local only; no push or deployment.
- **Changed:** added untracked static comparison HTML and this review note; briefly claimed and released the sample/report area in `robots_fighting.md`.
- **Verified:** source values and dates were read from committed `reports/sample-*` artifacts; the review mock preserves all nine scorecard rows and reconciles the impact sample to 10 actions.
- **Not verified:** visual rendering across browsers/print; source-level denominator definitions; any production behavior. No database, vendor API, report generator, or test suite was run.
