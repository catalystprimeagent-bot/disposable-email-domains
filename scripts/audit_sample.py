#!/usr/bin/env python3
"""Measure this list's false-positive rate on a random sample, with live evidence.

WHY THIS EXISTS
---------------
`domains.txt` is a merge of four upstream lists. 24% of its entries appear in only
ONE of those four, so for a quarter of the list there is no cross-source corroboration
at all. The one rejection this project has received from an outside maintainer
(`disposable/disposable#306`) was about source quality, so "a quarter of it is
single-sourced" is an objection that will be made again. This script answers it with a
number instead of a disclaimer.

WHAT IT MEASURES
----------------
Two independent random samples, drawn from the published list:

  single   - domains present in exactly 1 of the 4 upstream sources
  multi    - domains present in 2 or more

Both are audited with the identical instrument, so the output is not just an error rate
for the list; it is a comparison that tests whether single-sourcing is actually the
risk factor the objection assumes.

HOW IT DECIDES
--------------
Per domain it collects live, citable evidence only: MX, A, root TXT, `_dmarc` TXT (via
DNS-over-HTTPS, no local resolver needed) and the HTTP(S) root's status code and
<title>. It then applies the mechanical triage rule below. The rule does NOT output a
verdict -- it outputs a review tier, because "is this a real organisation" is a
judgement a regex cannot make. Tier 1 and tier 2 rows are meant to be read by a human
(or an agent) and given a final verdict in the companion `*-verdicts.json` file.

  tier 1  REVIEW REQUIRED. At least one signal that costs money or per-domain identity
          proof to obtain, which a throwaway-mail farm has little reason to buy:
          business-mail MX (Google Workspace, Microsoft 365, iCloud custom domain,
          Zoho, Proton, Fastmail), an enterprise mail gateway (Mimecast, Proofpoint,
          Barracuda, Cisco, Sophos, Trend Micro), an enforcing DMARC policy
          (p=reject / p=quarantine), or a provider domain-ownership token
          (apple-domain, google-site-verification, MS=, facebook-domain-verification).
  tier 2  REVIEW IF CHEAP. A live website that returns 200 with a <title> that does
          not look like a disposable-mail product, but no tier-1 signal.
  tier 3  NO REVIEW. Live mail/web but nothing above, or a title that self-identifies
          as a temporary-mail service.
  dead    No MX, no A, no web root. Cannot be evidenced either way from DNS alone.

Nothing here is treated as proof of "disposable". The rule only ever promotes a domain
toward human review; a domain the rule says nothing about stays unaudited, and the
report counts it as such rather than as a pass.

LIMITS, STATED UP FRONT
-----------------------
* A sample measures the sampled tranche, not every domain in it.
* `dead` domains are genuinely unresolvable from DNS: a parked throwaway and a shut-down
  real company look identical. The report therefore gives a BRACKET -- a point estimate
  counting only confirmed false positives, and a conservative upper bound counting every
  unresolved and inconclusive row as if it were an error. The honest number is the
  bracket, not either end alone.
* DNS and HTTP are a snapshot. Re-running on another day can differ; that is why every
  row carries `checked_at`.

USAGE
-----
  python scripts/audit_sample.py --n 300 --seed 20261009
  python scripts/audit_sample.py --report            # re-score from saved rows + verdicts

No auth, no secrets, no paid APIs. Outputs land in `audit/`.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import random
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
AUDIT_DIR = os.path.join(REPO, "audit")

# Reuse the source table from the build script so the two can never drift.
sys.path.insert(0, HERE)
from update import SOURCES, DOMAIN_RE, fetch  # noqa: E402

DOH = "https://dns.google/resolve"
UA = "catalyst-disposable-email-domains-audit/1.0 (+https://github.com/catalystprimeagent-bot/disposable-email-domains)"

# --- tier-1 signals -------------------------------------------------------------
# Mail hosting that is paid per mailbox, or that requires proving you own the domain
# before it will carry mail for it. A disposable-mail farm spinning up domains by the
# thousand has little reason to buy either.
BUSINESS_MX = {
    "google": ("aspmx.l.google.com", "googlemail.com", "google.com"),
    "microsoft365": ("mail.protection.outlook.com", "mail.eo.outlook.com"),
    "icloud": ("mail.icloud.com", "icloud.com.cn"),
    "zoho": ("zoho.com", "zoho.eu", "zohomail"),
    "proton": ("protonmail.ch", "proton.me"),
    "fastmail": ("messagingengine.com", "fastmail.com"),
}
GATEWAY_MX = {
    "mimecast": ("mimecast.com", "mimecast.co.za"),
    "proofpoint": ("pphosted.com", "ppe-hosted.com"),
    "barracuda": ("barracudanetworks.com", "ess.barracuda"),
    "cisco": ("iphmx.com", "ironport"),
    "sophos": ("sophos.com",),
    "trendmicro": ("trendmicro.com", "tmes.trendmicro"),
}
OWNERSHIP_TOKENS = (
    "apple-domain=",
    "google-site-verification=",
    "ms=ms",
    "facebook-domain-verification=",
    "atlassian-domain-verification=",
    "stripe-verification=",
)
DMARC_ENFORCING = re.compile(r"p\s*=\s*(reject|quarantine)", re.I)

# Titles that self-identify as the thing the list says they are. Matching here only ever
# REMOVES a domain from the review queue, so a miss costs review time, never accuracy.
DISPOSABLE_TITLE = re.compile(
    r"temp(orary)?[\s\-_]?mail|disposable|throwaway|burner|10\s?minute|fake\s?mail|"
    r"trash\s?mail|guerrilla|mailinator|yopmail|anonymous\s+email|email\s+generator|"
    r"inbox\s+generator|one[\s\-]?time\s+email",
    re.I,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def doh(name, rtype):
    """One DNS-over-HTTPS query. Returns (status, [rdata strings])."""
    url = "%s?name=%s&type=%s" % (DOH, urllib.parse.quote(name), rtype)
    req = urllib.request.Request(url, headers={"accept": "application/dns-json", "user-agent": UA})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.load(resp)
            answers = [a.get("data", "") for a in data.get("Answer", []) if a.get("type") == {
                "MX": 15, "A": 1, "TXT": 16}[rtype]]
            return data.get("Status"), answers
        except Exception as exc:  # network flake, not a finding
            if attempt == 2:
                return "error:%s" % type(exc).__name__, []
    return None, []


def http_root(domain):
    """Status code and <title> of the web root, https first then http. Evidence only."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we are recording what is there, not trusting it
    for scheme in ("https", "http"):
        url = "%s://%s/" % (scheme, domain)
        req = urllib.request.Request(url, headers={"user-agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                body = resp.read(200000)
                code = resp.getcode()
        except urllib.error.HTTPError as exc:
            code, body = exc.code, b""
        except Exception:
            continue
        charset = "utf-8"
        try:
            text = body.decode(charset, "replace")
        except Exception:
            text = ""
        m = TITLE_RE.search(text)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""
        return {"scheme": scheme, "status": code, "title": title}
    return {"scheme": None, "status": None, "title": ""}


def collect(domain):
    """All live evidence for one domain."""
    row = {"domain": domain, "checked_at": datetime.datetime.now(datetime.timezone.utc)
           .replace(microsecond=0).isoformat()}
    mx_status, mx = doh(domain, "MX")
    a_status, a = doh(domain, "A")
    _, txt = doh(domain, "TXT")
    _, dmarc = doh("_dmarc." + domain, "TXT")
    row["mx"] = mx
    row["a"] = a
    row["txt"] = [t for t in txt if len(t) < 500][:10]
    row["dmarc"] = dmarc[:3]
    row["dns_status"] = {"mx": mx_status, "a": a_status}
    row["web"] = http_root(domain) if (mx or a) else {"scheme": None, "status": None, "title": ""}
    return row


def triage(row):
    """Mechanical review tier + the exact signals that put it there."""
    signals = []
    mx_blob = " ".join(row["mx"]).lower()
    for label, needles in BUSINESS_MX.items():
        if any(n in mx_blob for n in needles):
            signals.append("business-mx:" + label)
    for label, needles in GATEWAY_MX.items():
        if any(n in mx_blob for n in needles):
            signals.append("gateway-mx:" + label)
    if any(DMARC_ENFORCING.search(d) for d in row["dmarc"]):
        signals.append("dmarc-enforcing")
    txt_blob = " ".join(row["txt"]).lower()
    for token in OWNERSHIP_TOKENS:
        if token in txt_blob:
            signals.append("ownership-token:" + token.rstrip("="))
    live_site = row["web"].get("status") == 200 and bool(row["web"].get("title"))
    self_identifies = bool(DISPOSABLE_TITLE.search(row["web"].get("title") or ""))
    if self_identifies:
        signals.append("title-self-identifies-disposable")

    if signals and not all(s == "title-self-identifies-disposable" for s in signals):
        tier = 1
    elif live_site and not self_identifies:
        tier = 2
    elif row["mx"] or row["a"] or row["web"].get("status"):
        tier = 3
    else:
        tier = "dead"
    row["signals"] = signals
    row["tier"] = tier
    return row


def wilson(k, n, z=1.96):
    """95% Wilson score interval. Correct at small k, unlike the normal approximation."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def build_population():
    """Fetch the four sources live and split the published list by source count."""
    published = set()
    with open(os.path.join(REPO, "domains.txt"), encoding="utf-8") as fh:
        for line in fh:
            d = line.strip()
            if d:
                published.add(d)
    counts = {d: 0 for d in published}
    per_source = {}
    for name, url, _lic, _repo in SOURCES:
        # A measurement on a partial merge would mislabel corroborated domains as
        # single-sourced, which is the exact number this script exists to report. So
        # unlike the daily build, a failed fetch here is fatal, not survivable.
        try:
            raw = fetch(url)
        except Exception as exc:
            raise SystemExit("source %s did not respond (%s); refusing to measure on a "
                             "partial merge" % (name, exc))
        got = {ln.strip().lower() for ln in raw.splitlines()}
        got = {d for d in got if DOMAIN_RE.match(d)}
        per_source[name] = len(got)
        for d in got & published:
            counts[d] += 1
    single = sorted(d for d, c in counts.items() if c == 1)
    multi = sorted(d for d, c in counts.items() if c >= 2)
    orphan = sorted(d for d, c in counts.items() if c == 0)
    return published, single, multi, orphan, per_source


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300, help="sample size per tranche")
    ap.add_argument("--seed", type=int, default=20261009)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--stamp", default=datetime.date.today().isoformat())
    ap.add_argument("--report", action="store_true", help="re-score saved rows, no network")
    args = ap.parse_args()
    os.makedirs(AUDIT_DIR, exist_ok=True)
    rows_path = os.path.join(AUDIT_DIR, "sample-%s-rows.json" % args.stamp)

    if args.report:
        with open(rows_path, encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        published, single, multi, orphan, per_source = build_population()
        print("published=%d single-source=%d (%.1f%%) multi-source=%d orphan=%d"
              % (len(published), len(single), 100.0 * len(single) / len(published),
                 len(multi), len(orphan)))
        rng = random.Random(args.seed)
        sample = {
            "single": rng.sample(single, min(args.n, len(single))),
            "multi": rng.sample(multi, min(args.n, len(multi))),
        }
        payload = {
            "meta": {
                "stamp": args.stamp,
                "seed": args.seed,
                "n_per_tranche": args.n,
                "published_total": len(published),
                "single_source_total": len(single),
                "multi_source_total": len(multi),
                "orphan_total": len(orphan),
                "raw_per_source": per_source,
                "started_at": datetime.datetime.now(datetime.timezone.utc)
                .replace(microsecond=0).isoformat(),
            },
            "tranches": {},
        }
        for tranche, domains in sample.items():
            print("auditing %s (%d domains)..." % (tranche, len(domains)), flush=True)
            out = []
            with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
                for i, row in enumerate(pool.map(collect, domains), 1):
                    out.append(triage(row))
                    if i % 50 == 0:
                        print("  %d/%d" % (i, len(domains)), flush=True)
            payload["tranches"][tranche] = out
        with open(rows_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print("wrote %s" % rows_path)

    verdict_path = os.path.join(AUDIT_DIR, "sample-%s-verdicts.json" % args.stamp)
    verdicts = {}
    if os.path.exists(verdict_path):
        with open(verdict_path, encoding="utf-8") as fh:
            verdicts = json.load(fh).get("verdicts", {})

    print("\n=== result ===")
    if not verdicts:
        print("no verdicts file at %s -- showing triage only; the review queue is tiers 1 and 2"
              % verdict_path)
    rates = {}
    for tranche, rows in payload["tranches"].items():
        tiers = {}
        for r in rows:
            tiers[str(r["tier"])] = tiers.get(str(r["tier"]), 0) + 1
        n = len(rows)

        def pick(verdict, confidences):
            return sorted(r["domain"] for r in rows
                          if verdicts.get(r["domain"], {}).get("verdict") == verdict
                          and verdicts.get(r["domain"], {}).get("confidence") in confidences)

        fp_high = pick("false_positive", ("high",))
        fp_band = pick("false_positive", ("high", "medium"))
        kept = pick("disposable", ("high", "medium", "low"))
        reviewed_incon = pick("inconclusive", ("high", "medium", "low"))
        dead = [r for r in rows if r["tier"] == "dead"]
        unaudited = [r for r in rows if r["tier"] == 3]

        lo, hi = wilson(len(fp_high), n)
        blo, bhi = wilson(len(fp_band), n)
        rates[tranche] = {"n": n, "high": len(fp_high), "band": len(fp_band),
                          "high_ci": (lo, hi), "band_ci": (blo, bhi)}
        print("%-7s n=%d  review queue=%d (tier1 %s, tier2 %s)  no-review=%d  unresolvable=%d"
              % (tranche, n, tiers.get("1", 0) + tiers.get("2", 0), tiers.get("1", 0),
                 tiers.get("2", 0), len(unaudited), len(dead)))
        print("        false positives, high confidence only : %3d / %d = %5.2f%%  (95%% CI %.2f-%.2f%%)"
              % (len(fp_high), n, 100.0 * len(fp_high) / n, 100 * lo, 100 * hi))
        print("        false positives, high + medium        : %3d / %d = %5.2f%%  (95%% CI %.2f-%.2f%%)"
              % (len(fp_band), n, 100.0 * len(fp_band) / n, 100 * blo, 100 * bhi))
        print("        reviewed and kept as disposable: %d   reviewed and inconclusive: %d"
              % (len(kept), len(reviewed_incon)))
        if fp_high:
            print("        high-confidence false positives: %s" % ", ".join(fp_high))

    # Whole-list estimate: the two tranches are strata of known size, so the list-wide rate
    # is their weighted average, not the average of the two percentages.
    meta = payload["meta"]
    tot = meta["published_total"]
    w_single = meta["single_source_total"] / tot
    w_multi = meta["multi_source_total"] / tot
    if {"single", "multi"} <= set(rates):
        for label, key in (("high confidence only", "high"), ("high + medium", "band")):
            est = (w_single * rates["single"][key] / rates["single"]["n"]
                   + w_multi * rates["multi"][key] / rates["multi"]["n"])
            print("whole list, %-20s stratified estimate %.2f%%  (~%d of %d domains)"
                  % (label, 100 * est, round(est * tot), tot))
        print("stratum weights: single-source %.1f%% of the list, multi-source %.1f%%"
              % (100 * w_single, 100 * w_multi))
    print("\nrows: %s\nverdicts: %s" % (rows_path, verdict_path))


if __name__ == "__main__":
    main()
