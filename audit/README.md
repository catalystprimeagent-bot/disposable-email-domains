# How accurate is this list? A measured answer

Date of measurement: **2026-10-09**. Re-runnable: `python scripts/audit_sample.py`.

Most disposable-email lists, this one included, tell you how many domains they have and
nothing about how often they are wrong. This folder is the other number. It is produced by
sampling the published list at random, checking each sampled domain against live DNS and
its live website, and reporting the error rate with a confidence interval.

## The headline

| | share of list | false positives, high confidence | upper band (high + medium) |
| --- | --- | --- | --- |
| Single-sourced (1 of 4 upstream sources) | 23,031 of 96,431 (23.9%) | **8.33%** (25/300, 95% CI 5.71-12.01%) | 18.00% (54/300, 95% CI 14.07-22.74%) |
| Corroborated (2+ sources) | 73,234 of 96,431 (75.9%) | **1.00%** (3/300, 95% CI 0.34-2.90%) | 3.67% (11/300, 95% CI 2.06-6.45%) |
| **Whole list** (stratified estimate) | 96,431 | **2.75%** (~2,650 domains) | 7.08% (~6,830 domains) |

A "false positive" means the domain belongs to an organisation, product or person using it
for their **own** mail, so blocking it blocks real correspondence. The 25 single-sourced
ones found in this sample include a US commercial insurer, a drinks manufacturer's Turkish
arm, a litigation-support consultancy, a Miami bike shop, a Brussels beauty salon, a Krakow
chip shop, a dental practice, an Iowa Lutheran church and a subdomain of an accredited
Indian university.

The two confidence intervals do not overlap. **Single-sourcing is not a theoretical concern
about provenance. It is an 8x measured difference in how often the list is wrong.**

## What we did about it

1. **The 28 high-confidence false positives are removed.** They are in
   `scripts/update.py` `EXCLUSIONS`, with their live DNS and HTTP evidence in
   `false-positive-evidence.json`. Removing them fixes those 28 domains. It does **not**
   move the rates above, and we are not going to present it as if it did: the sample found
   28, the population still contains an estimated 2,650.
2. **`domains-strict.txt` now exists.** Same build, same licences, same daily refresh, but
   only the 73,231 domains that two or more independent sources agree on. Its measured
   high-confidence false-positive rate is 1.00% against 2.75% for the full list. If a false
   positive costs you a real customer, use the strict file.
3. **The 29 medium-confidence findings were deliberately left in the list.** They are real
   findings, they are counted in the upper band, and they are not removed, because each
   rests on a single evidence leg. Removing thousands of domains on one leg is how a list
   earns the opposite reputation.

## Which file should you use?

The honest trade is not "strict is better". It is a different trade in each direction, and
the audit found the reason:

- **8.3% of single-sourced domains have no DNS at all. 61% of corroborated ones have none.**
  The corroborated majority is largely long-dead throwaway domains that every upstream list
  copied from every other. The single-sourced quarter is where the *currently live* domains
  are, both the active throwaway services and the real businesses.
- So `domains.txt` catches more live throwaway providers **and** more real businesses.
  `domains-strict.txt` is the conservative file: fewer wrong blocks, more misses.

Pick on cost. Signup abuse on a free tier: the full list, where a wrong block costs little.
A checkout, a quote form, a support inbox: the strict list.

## Method

`scripts/audit_sample.py`, run as
`python scripts/audit_sample.py --n 300 --seed 20261009 --stamp 2026-10-09`.

1. **Population.** The four upstream sources are fetched live and intersected with the
   published `domains.txt`, giving each published domain a source count. A fetch failure is
   fatal here (unlike in the daily build), because a missing source would relabel
   corroborated domains as single-sourced, which is the exact number being measured.
2. **Sample.** 300 domains from each tranche, `random.Random(20261009).sample`. The seed is
   recorded so the same sample can be drawn again.
3. **Evidence per domain.** MX, A, root TXT and `_dmarc` TXT over DNS-over-HTTPS (no local
   resolver required, so the script behaves the same on any machine), then an HTTP(S) fetch
   of the web root for its status code and `<title>`. Everything recorded with a UTC
   timestamp in `sample-2026-10-09-rows.json`.
4. **Mechanical triage into review tiers**, not verdicts. Tier 1 is any signal that costs
   money or per-domain identity proof: business-mail MX (Google Workspace, Microsoft 365,
   iCloud custom domain, Zoho, Proton, Fastmail), an enterprise mail gateway (Mimecast,
   Proofpoint, Barracuda, Cisco, Sophos, Trend Micro), an enforcing DMARC policy, or a
   provider domain-ownership token. Tier 2 is a live site with a title and no tier-1 signal.
   Tier 3 is live but unremarkable. `dead` is no MX, no A, no web root.
5. **Human verdict on every tier-1 and tier-2 row**, recorded with its reasoning in
   `sample-2026-10-09-verdicts.json`. 169 rows reviewed, 169 verdicts, no gaps.
   **high** confidence requires two independent legs: a live web root naming a distinct
   real-world organisation, product or person matching the domain, **and** mail hosting that
   is paid per mailbox or an enterprise gateway. One leg alone is **medium**.
6. **Rate with a Wilson 95% interval** (correct at small counts, unlike the normal
   approximation), then a stratified whole-list estimate weighted by each tranche's real
   share of the list.

## Full breakdown

| | single-sourced | corroborated |
| --- | --- | --- |
| sampled | 300 | 300 |
| tier 1 (reviewed) | 71 | 22 |
| tier 2 (reviewed) | 48 | 28 |
| tier 3 (live, not reviewed) | 156 | 67 |
| `dead`, no DNS and no web root | 25 | 183 |
| verdict: false positive, high | 25 | 3 |
| verdict: false positive, medium | 29 | 8 |
| verdict: correctly listed as disposable | 26 | 16 |
| verdict: inconclusive | 39 | 23 |

## What this does not measure, stated plainly

- **It is a sample.** 300 of 23,031 and 300 of 73,234. The confidence intervals are the
  honest width of the answer; the point estimates are not exact counts.
- **It only measures false positives, never misses.** Nothing here says how many disposable
  domains the list fails to contain. That is a different and harder measurement, because it
  needs a source of truth about domains that are *not* in any list.
- **Tier 3 rows were not reviewed at all.** 156 single-sourced and 67 corroborated domains
  were live but showed no tier-1 or tier-2 signal. The report counts them as unaudited, not
  as correct. If some of them are false positives, the true rate is higher than the point
  estimate, which is part of why the upper band is published alongside it.
- **`dead` rows cannot be settled from DNS.** A parked throwaway domain and a shut-down real
  company look identical. They are excluded from the numerator and reported separately.
- **62 rows came back inconclusive even after review** (39 single, 23 corroborated): parked
  pages, for-sale listings, host default pages, expired corporate domains now serving
  unrelated content, and titles that only repeat the domain name. They are counted as
  inconclusive, not as passes.
- **Judgement is in the loop.** Steps 1 to 4 are mechanical and reproducible; step 5 is a
  human reading evidence. Each verdict carries its reasoning in the verdicts file so you can
  disagree with a specific one rather than with the number.
- **DNS and HTTP are a snapshot.** Every row carries `checked_at`. A re-run on another day
  will differ at the margin.
- **Two known gaps in the triage rule** are written down in `known_rule_gaps` in the
  verdicts file, including one title pattern the regex misses. Both cost review time rather
  than accuracy.

## Files

- `sample-2026-10-09-rows.json`: every sampled domain with its raw live evidence and tier.
- `sample-2026-10-09-verdicts.json`: the 169 human verdicts, each with its reasoning.
- `../scripts/audit_sample.py`: the measurement. `--report` re-scores from saved rows with
  no network access.
- `../scripts/promote_audit_exclusions.py`: turns high-confidence verdicts into evidence
  entries and the exclusion list. Dry run by default.
