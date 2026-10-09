#!/usr/bin/env python3
"""Regenerate domains.txt and domains.json from cleared upstream sources.

Run by .github/workflows/update.yml on a schedule, and by hand for the first build.
No auth, no secrets, no paid APIs: every source below is a public raw file on GitHub,
fetched over plain HTTPS.

SOURCE / LICENCE DISCIPLINE (see README.md "Sources" table for the full writeup):
Only sources whose GitHub-reported licence is a known permissive licence (MIT here) are
included. A source with no detected licence is not addable just because it is public on
GitHub -- "it's on GitHub" is not a licence. If GitHub stops reporting a licence for one
of these repos, or a fetch starts failing, drop it rather than guessing.
"""
import json
import re
import sys
import urllib.error
import urllib.request

# Each entry: (short name, raw file URL, licence, source repo URL).
# Licence checked via `GET https://api.github.com/repos/<owner>/<repo>` -> `license.spdx_id`
# on 2026-10-02. Three are SPDX "MIT"; the fourth is CC0-1.0 (public domain dedication),
# whose LICENSE.txt was read directly because GitHub reports it as NOASSERTION/"other".
SOURCES = [
    (
        "disposable/disposable-email-domains",
        "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
        "MIT",
        "https://github.com/disposable/disposable-email-domains",
    ),
    (
        "FGRibreau/mailchecker",
        "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt",
        "MIT",
        "https://github.com/FGRibreau/mailchecker",
    ),
    (
        "wesbos/burner-email-providers",
        "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt",
        "MIT",
        "https://github.com/wesbos/burner-email-providers",
    ),
    # Formerly martenson/disposable-email-domains; the owner renamed to an org, so the old
    # path 404s and the GitHub API only reveals the new name via the redirect. Do not drop
    # this source on a 404 -- follow the redirect. GitHub reports NOASSERTION ("other")
    # because its licence lives in LICENSE.txt, but that file is the verbatim CC0 1.0
    # public-domain dedication, which permits redistribution outright.
    (
        "disposable-email-domains/disposable-email-domains",
        "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
        "CC0-1.0",
        "https://github.com/disposable-email-domains/disposable-email-domains",
    ),
]

# Loose but real domain-shape check: lowercase labels, dots, no leading/trailing hyphen
# per label. Rejects obvious junk lines (blank, comments, stray whitespace, full emails)
# without being a strict RFC validator -- this is a block list, not a DNS resolver.
DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)

# Sanity floor: if the merged, validated list is smaller than this, something upstream
# broke (empty response, format change, redirect to an HTML error page). Refuse to
# overwrite a good list with a bad one -- fail the workflow step instead.
MIN_DOMAINS = 10000

# Never-disposable guard. This list updates itself daily and commits without review, so a
# single bad upstream entry would ship a false positive on a major provider and quietly
# break every consumer blocking on it. Any of these appearing in the merged set means an
# upstream source is wrong: fail the build loudly rather than publish it.
NEVER_DISPOSABLE = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.co.uk", "hotmail.com",
    "hotmail.co.uk", "live.com", "live.co.uk", "msn.com", "yahoo.com", "yahoo.co.uk",
    "yahoo.co.jp", "ymail.com", "rocketmail.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "protonmail.com", "protonmail.ch", "proton.me", "pm.me", "zoho.com",
    "gmx.com", "gmx.de", "gmx.net", "mail.com", "mail.ru", "fastmail.com", "hey.com",
    "tutanota.com", "tuta.io", "yandex.ru", "yandex.com", "qq.com", "163.com",
    "126.com", "sina.com", "web.de", "t-online.de", "comcast.net", "verizon.net",
    "att.net", "sbcglobal.net", "bellsouth.net", "cox.net", "charter.net",
    "btinternet.com", "sky.com", "virginmedia.com", "orange.fr", "wanadoo.fr",
    "free.fr", "laposte.net", "libero.it", "virgilio.it", "naver.com", "daum.net",
    "hanmail.net", "rediffmail.com", "shaw.ca", "rogers.com", "sympatico.ca",
    "telus.net", "bigpond.com", "optusnet.com.au",
}

# Exclusion stage. Separate mechanism from NEVER_DISPOSABLE above: this SUBTRACTS known
# false positives from the merged set before the tripwire runs, rather than failing the
# build. Source: disposable/disposable's own hand-curated whitelist.txt
# (https://github.com/disposable/disposable/blob/master/whitelist.txt), domains their
# maintainers manually reviewed and removed as not actually disposable. That repo is
# MIT-licensed (confirmed by reading its LICENSE file directly, not just GitHub's detected
# label -- Copyright (c) 2017 Andrei Simionescu; Stefan Meinecke, greenSec GmbH), which
# permits this redistribution; this notice is the attribution MIT requires.
#
# Found 2026-10-05: our own merged list reintroduced 16 of these 39 domains (41%),
# including asics.com and nus.edu.sg, because our sources overlap/derive from
# disposable/disposable's own pipeline with none of its manual whitelist review applied.
# Flagged by maintainer smeinecke declining disposable/disposable#306. Snapshot taken
# 2026-10-05; re-sync periodically as that file grows.
EXCLUSIONS = {
    "angi.com", "asics.com", "benilde.edu.ph", "brainonfire.net", "buildingradar.com",
    "cbamboo.com", "centraldecomunicacion.es", "com.ar", "deity.co.nz", "e2estudios.com",
    "fake.com", "feedspot.com", "feedspotmailer.com", "file-up.fr", "forwardemail.net",
    "gide.com", "home.de", "icam.fr", "ke.com", "lendscape.com", "lilo.org",
    "lionelastomers.com", "mail.htl22.at", "msn.co.uk", "nus.edu.sg", "purple.dev",
    "ruffrey.com", "samsung.com", "shitware.nl", "sibmail.com", "swatch.com",
    "tmxnet.com", "ubicloud.com", "wizard.com", "xwaretech.com", "xwaretech.info",
    "xwaretech.net", "xwaretech.tk", "zoho.com",
    # Found independently 2026-10-09 (not from disposable/disposable's whitelist.txt --
    # these are our own catch), by auditing our own published list against itself after a
    # contribution run flagged two of them as side findings. Live DNS/MX/HTTP evidence for
    # each is in false-positive-evidence.json. continumail.com and mail3x.com: real small
    # business/personal domains with enterprise-grade MX. grad.bryant.edu: a live subdomain
    # of Bryant University (accredited US .edu, Google Workspace MX) -- found by a targeted
    # sweep for .edu/.edu.*/.ac.*/.gov* entries after the first two were flagged; see that
    # sweep's writeup for why the other 328 hits in the same screen were left alone.
    "continumail.com", "mail3x.com", "grad.bryant.edu",
    # Found 2026-10-09 by the random-sample audit (scripts/audit_sample.py, written up in
    # audit/README.md). These are the 28 domains the audit confirmed at HIGH confidence,
    # meaning two independent legs: a live web root naming a real-world organisation,
    # person or product, AND mail hosting that is paid per mailbox or an enterprise
    # gateway. Per-domain live DNS/HTTP evidence for each is in
    # false-positive-evidence.json. The audit's 29 MEDIUM-confidence findings rest on one
    # leg only and are deliberately NOT here: they are published as an upper band instead,
    # because removing thousands of domains on one leg is how a list earns the opposite
    # reputation. Promote one only with a second leg added.
    "aiitkkd.aditya.ac.in", "alcames.org", "biofitstudios.com", "chelsworth.net",
    "coffeejeans.com.ua", "doitagile.com", "edarnell.com", "elitecycling.net",
    "fayatpartievi.com", "frytkibelgijskie.pl", "gcbcdiet.com", "gesdonerkebap.com",
    "heidithorsen.com", "heightsdentalsmiles.com", "kangu24.com", "medha.com",
    "mey.com.tr", "novibet.com", "oilsandherbs.co.uk", "onegroupconsultoria.com.br",
    "ppz.pl", "roastersmap.com", "sakuracare.be", "silvertigerconsulting.com",
    "studenttimes.com", "texasturbine.com", "tmfin.com", "ufginsurance.com",
}


def fetch(url, timeout=30, retries=2):
    last_exc = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "catalyst-disposable-email-domains/1 (+build script)"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            last_exc = exc
    raise last_exc


def main():
    merged = set()
    per_source_counts = {}
    # How many of the four sources list each domain. A domain only one source has ever
    # seen has no corroboration at all, and a random-sample audit on 2026-10-09 measured
    # those entries at 8.3% false positives against 1.0% for corroborated ones
    # (audit/README.md). That gap is why domains-strict.txt exists: same build, same
    # licences, but only domains two or more independent sources agree on.
    source_count = {}
    failures = []

    for name, url, licence, repo in SOURCES:
        try:
            text = fetch(url)
        except Exception as exc:  # noqa: BLE001 - log and continue with other sources
            print("WARN: failed to fetch %s (%s): %s" % (name, url, exc), file=sys.stderr)
            failures.append(name)
            continue

        count = 0
        seen_here = set()
        for line in text.splitlines():
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            if DOMAIN_RE.match(d):
                merged.add(d)
                count += 1
                # Per SOURCE, not per line: a source that lists a domain twice must not
                # look like two sources agreeing.
                if d not in seen_here:
                    seen_here.add(d)
                    source_count[d] = source_count.get(d, 0) + 1
        per_source_counts[name] = count
        print("%s: %d domains" % (name, count))

    if not merged:
        print("ERROR: no domains collected from any source, all %d sources failed" % len(SOURCES), file=sys.stderr)
        sys.exit(1)

    excluded_present = sorted(merged & EXCLUSIONS)
    merged -= EXCLUSIONS
    if excluded_present:
        print(
            "Excluded %d known false positive(s) (upstream whitelist + our own audits): %s"
            % (len(excluded_present), ", ".join(excluded_present))
        )

    if len(merged) < MIN_DOMAINS:
        print(
            "ERROR: merged list has only %d domains (floor is %d) -- refusing to write, "
            "likely an upstream format break" % (len(merged), MIN_DOMAINS),
            file=sys.stderr,
        )
        sys.exit(1)

    false_positives = sorted(merged & NEVER_DISPOSABLE)
    if false_positives:
        print(
            "ERROR: an upstream source lists %d known-real provider(s) as disposable: %s\n"
            "Refusing to publish. Find which source added them, drop or filter it, and "
            "open an issue upstream." % (len(false_positives), ", ".join(false_positives)),
            file=sys.stderr,
        )
        sys.exit(1)

    domains = sorted(merged)

    with open("domains.txt", "w", encoding="utf-8") as f:
        for d in domains:
            f.write(d + "\n")

    with open("domains.json", "w", encoding="utf-8") as f:
        json.dump(domains, f, indent=0)
        f.write("\n")

    print("Wrote %d unique domains to domains.txt and domains.json" % len(domains))

    # Corroborated subset. Only meaningful when every source answered: with a source
    # missing, domains it alone carries would be dropped and domains it corroborated would
    # look single-sourced, so the file would be wrong in both directions. Skip it instead
    # of publishing a misleading one, and leave the previous good file in place.
    if failures:
        print(
            "Skipped domains-strict.txt: %d source(s) failed this run, so source counts "
            "are not trustworthy. Leaving the previous strict files untouched."
            % len(failures),
            file=sys.stderr,
        )
    else:
        strict = [d for d in domains if source_count.get(d, 0) >= 2]
        if len(strict) < MIN_DOMAINS:
            print(
                "ERROR: strict list has only %d domains (floor is %d) -- refusing to "
                "write it" % (len(strict), MIN_DOMAINS),
                file=sys.stderr,
            )
            sys.exit(1)
        with open("domains-strict.txt", "w", encoding="utf-8") as f:
            for d in strict:
                f.write(d + "\n")
        with open("domains-strict.json", "w", encoding="utf-8") as f:
            json.dump(strict, f, indent=0)
            f.write("\n")
        single = len(domains) - len(strict)
        print(
            "Wrote %d corroborated domains (2+ sources) to domains-strict.txt and "
            "domains-strict.json; %d single-sourced domains (%.1f%%) are in the full "
            "list only" % (len(strict), single, 100.0 * single / len(domains))
        )
    if failures:
        print("Sources that failed this run (kept going on the rest): %s" % ", ".join(failures))


if __name__ == "__main__":
    main()
