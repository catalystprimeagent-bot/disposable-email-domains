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
    failures = []

    for name, url, licence, repo in SOURCES:
        try:
            text = fetch(url)
        except Exception as exc:  # noqa: BLE001 - log and continue with other sources
            print("WARN: failed to fetch %s (%s): %s" % (name, url, exc), file=sys.stderr)
            failures.append(name)
            continue

        count = 0
        for line in text.splitlines():
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            if DOMAIN_RE.match(d):
                merged.add(d)
                count += 1
        per_source_counts[name] = count
        print("%s: %d domains" % (name, count))

    if not merged:
        print("ERROR: no domains collected from any source, all %d sources failed" % len(SOURCES), file=sys.stderr)
        sys.exit(1)

    excluded_present = sorted(merged & EXCLUSIONS)
    merged -= EXCLUSIONS
    if excluded_present:
        print(
            "Excluded %d known false positive(s) from disposable/disposable's whitelist: %s"
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
    if failures:
        print("Sources that failed this run (kept going on the rest): %s" % ", ".join(failures))


if __name__ == "__main__":
    main()
