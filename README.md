# disposable-email-domains

A maintained, machine-readable list of disposable / throwaway / temporary email domains.
97,918 domains as of the last update, merged and de-duplicated from four permissively
licensed upstream lists, auto-refreshed daily by GitHub Actions.

- `domains.txt`: one lowercase domain per line, sorted, newline-terminated.
- `domains.json`: the same list as a JSON array of strings.

## Use it

```bash
curl -s https://raw.githubusercontent.com/catalystprimeagent-bot/disposable-email-domains/main/domains.txt
```

```python
import json, urllib.request

DOMAINS = set(json.load(urllib.request.urlopen(
    "https://raw.githubusercontent.com/catalystprimeagent-bot/disposable-email-domains/main/domains.json"
)))

def is_disposable(address):
    return address.rsplit("@", 1)[-1].strip().lower() in DOMAINS
```

```javascript
const domains = new Set(
  await fetch(
    "https://raw.githubusercontent.com/catalystprimeagent-bot/disposable-email-domains/main/domains.json"
  ).then((r) => r.json())
);

const isDisposable = (address) =>
  domains.has(address.split("@").pop().trim().toLowerCase());
```

Load the list once and keep it in a set. It is about 98,000 entries, so a linear scan per
address (`Array.prototype.includes`, or `in` on a Python list) gets slow fast.

## How it is built

`scripts/update.py` fetches each source below, lower-cases and validates every line as a
domain (rejecting blanks, comments, and anything that is not a plausible domain shape),
merges them into one de-duplicated, sorted set, and writes `domains.txt` and
`domains.json`. A GitHub Actions workflow (`.github/workflows/update.yml`) runs that
script once a day and commits the result only if it changed, so the list stays current
with no recurring human work.

Four things protect the list from a bad upstream day, because the build commits without
human review:

- If a source stops responding, the build continues on the remaining sources.
- If the merged result falls below a floor of 10,000 domains, the build fails rather than
  overwrite a good list with a broken one.
- **An exclusion stage removes known false positives before publishing**, rather than
  failing the build. Source: `disposable/disposable`'s own hand-curated
  [`whitelist.txt`](https://github.com/disposable/disposable/blob/master/whitelist.txt) —
  domains its maintainers manually reviewed and removed as not actually disposable
  (MIT-licensed, reused with attribution). Found 2026-10-05: our merge had silently
  reintroduced 16 of those 39 domains, including `asics.com` and `nus.edu.sg`, because our
  own sources overlap with that project's pipeline but without its manual review applied.
  Flagged by a maintainer declining our PR to that repo — credited in the commit that
  fixed it.
- If any source ever lists one of ~66 major global providers (`gmail.com`, `outlook.com`
  and similar large webmail/ISP domains) as disposable, the build fails and publishes
  nothing rather than ship that one case. **This is a narrow tripwire for one catastrophic
  failure mode, not general false-positive protection** — it only covers those ~66
  specific domains and would not have caught the `asics.com` / `nus.edu.sg` problem above,
  which is why the exclusion stage exists as a separate mechanism.

## False-positive evidence

`false-positive-evidence.json` is a machine-readable, per-domain evidence file: for each
domain known to have been wrongly shipped as "disposable" by this list (or by the
upstream lists it merges), it records what was actually checked -- live MX/A records and,
where a web root exists, an HTTP status and page title -- with a timestamp and a
confidence level. It is not a claim about our own data; it is evidence about specific
domains, citable on its own regardless of what list you maintain.

Two rules this file follows, because an earlier PR of ours overclaimed a safeguard and a
maintainer caught it:

- **Every entry has a timestamped check, not just a citation.** "A maintainer removed it
  once" is the starting point (`provenance`), not the evidence (`evidence`).
- **Confidence is reported honestly, including when it is low.** Three of the sixteen
  entries currently in the file are marked `medium`, `low`, or `none` because tonight's
  check could not fully support them (one domain does not currently resolve at all). They
  are kept in the file and flagged rather than quietly dropped or rounded up.

Consume it directly if you maintain a similar list and want to check your own false
positives against ours:

```bash
curl -s https://raw.githubusercontent.com/catalystprimeagent-bot/disposable-email-domains/main/false-positive-evidence.json
```

## Sources and licences

Every domain in this list comes from a source whose licence explicitly permits
redistribution. "It's public on GitHub" is not a licence by itself. Each row below records
the licence that source actually grants, verified 2026-10-02 against both the GitHub API
(`GET /repos/<owner>/<repo>`, field `license.spdx_id`) and the repository's own licence
file.

| Source | Licence | Raw domains | Notes |
| --- | --- | --- | --- |
| [disposable/disposable-email-domains](https://github.com/disposable/disposable-email-domains) | MIT | 97,735 | Copyright (c) 2017 Andrei Simionescu; Stefan Meinecke, greenSec GmbH. Largest single source. |
| [FGRibreau/mailchecker](https://github.com/FGRibreau/mailchecker) | MIT | 56,331 | Copyright (c) 2013 Francois-Guillaume Ribreau. Cross-language disposable-email detection list. |
| [wesbos/burner-email-providers](https://github.com/wesbos/burner-email-providers) | MIT | 27,277 | Burner / temporary email provider list. |
| [disposable-email-domains/disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) | CC0-1.0 | 9,199 | Public-domain dedication, no copyright reserved. Formerly `martenson/disposable-email-domains`. |

Merged, de-duplicated and validated as domain-shaped, then reduced by the exclusion stage above: **97,918 unique domains**.

The three MIT sources permit redistribution, modification and merging provided the
copyright and permission notice is preserved, which is why their notices are reproduced
above rather than only linked. The CC0 source waives copyright entirely and carries no
attribution requirement; it is credited anyway. This repository's own code and the merged
output are MIT-licensed separately: see `LICENSE`.

One note on that CC0 source, because it is an easy mistake to repeat: GitHub reports its
licence as `NOASSERTION` ("other") rather than `CC0-1.0`, because the dedication lives in
`LICENSE.txt` in a form GitHub's detector does not match. The file itself is the verbatim
CC0 1.0 Universal text. Trusting the API field alone would have wrongly excluded a
public-domain list.

### Dropped sources

- **ivolo/disposable-email-domains**: GitHub reports no detected licence (`license` is
  `null`, no licence file in the repository). With no explicit grant, default copyright
  applies and redistribution is not permitted. Dropped, not merged.
- **unsubscribe/disposable-email-domains**: the repository no longer exists at that path
  and returns 404 with no redirect. Not merged.

A smaller, legally clean list beats a larger one that cannot be redistributed, so these
were left out rather than merged and footnoted.

## Checking a specific address, not just a domain

This list only tells you whether a *domain* is a known disposable provider. If you need to
check whether one specific email address is real, covering syntax, MX records and mailbox
deliverability, that is a different and harder problem. We built
[`catalyst_prime/email-verifier`](https://apify.com/catalyst_prime/email-verifier) on the
Apify Store for exactly that.

## Licence

This repository's own code and compiled output are MIT-licensed (`LICENSE`). The
underlying domain data is drawn from the permissively licensed sources listed above, with
their copyright notices preserved as required.
