#!/usr/bin/env python3
"""Turn high-confidence audit false positives into evidence-file entries + an exclusion list.

`scripts/audit_sample.py` measures a rate; this turns the individual findings into the two
artefacts a consumer can act on:

  1. new entries appended to `false-positive-evidence.json`, each carrying the live DNS/HTTP
     evidence actually recorded at audit time, not a re-check and not a claim;
  2. the exact `EXCLUSIONS` literal to paste into `scripts/update.py`, printed to stdout.

ONLY `confidence: "high"` verdicts are promoted. Medium ones are real findings but they rest
on one evidence leg, and removing 29 domains on one leg is how a list earns the opposite
reputation. They stay in the audit file, counted in the reported upper band, and unexcluded.

  python scripts/promote_audit_exclusions.py --stamp 2026-10-09 [--write]

Without --write it prints what it would do and changes nothing.
"""
import argparse
import datetime
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamp", required=True)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    audit = os.path.join(REPO, "audit")
    with open(os.path.join(audit, "sample-%s-rows.json" % args.stamp), encoding="utf-8") as fh:
        rows_doc = json.load(fh)
    with open(os.path.join(audit, "sample-%s-verdicts.json" % args.stamp), encoding="utf-8") as fh:
        verdicts_doc = json.load(fh)
    verdicts = verdicts_doc["verdicts"]
    rows = {r["domain"]: (tranche, r)
            for tranche, rs in rows_doc["tranches"].items() for r in rs}

    ev_path = os.path.join(REPO, "false-positive-evidence.json")
    with open(ev_path, encoding="utf-8") as fh:
        evidence = json.load(fh)
    already = {e["domain"] for e in evidence["entries"]}

    promote = sorted(d for d, v in verdicts.items()
                     if v["verdict"] == "false_positive" and v["confidence"] == "high")
    new_entries = []
    for domain in promote:
        if domain in already:
            print("skip %s: already in false-positive-evidence.json" % domain)
            continue
        tranche, row = rows[domain]
        web = row["web"]
        new_entries.append({
            "domain": domain,
            "claim": "not a disposable/temporary email domain",
            "provenance": {
                "originally_removed_by": "catalystprimeagent-bot, own random-sample audit",
                "audit": "audit/sample-%s-rows.json + sample-%s-verdicts.json" % (args.stamp, args.stamp),
                "method": "stratified random sample of the published list, seed %s, n=%s per tranche"
                          % (rows_doc["meta"]["seed"], rows_doc["meta"]["n_per_tranche"]),
                "upstream_corroboration": "%s-source tranche" % tranche,
                "found_in_our_list": "domains.txt as published on %s" % args.stamp,
            },
            "checked_at": row["checked_at"],
            "checked_by": "catalystprimeagent-bot (live DNS-over-HTTPS + HTTP, audit run)",
            "evidence": {
                "mx_records": row["mx"],
                "a_records": row["a"],
                "dmarc_txt": row["dmarc"],
                "root_txt": row["txt"],
                "http": {"scheme": web.get("scheme"), "status": web.get("status"),
                         "title": web.get("title")},
                "triage_signals": row["signals"],
            },
            "confidence": "high",
            "reasoning": verdicts[domain]["basis"],
        })

    print("\n%d new evidence entries (%d promoted, %d already present)"
          % (len(new_entries), len(promote), len(promote) - len(new_entries)))
    print("\n--- paste into scripts/update.py EXCLUSIONS ---")
    line = ""
    for domain in promote:
        piece = '"%s", ' % domain
        if len(line) + len(piece) > 86:
            print("    " + line.rstrip())
            line = ""
        line += piece
    if line:
        print("    " + line.rstrip().rstrip(","))
    print("--- end ---\n")

    if not args.write:
        print("dry run; pass --write to append the evidence entries")
        return
    evidence["entries"].extend(new_entries)
    evidence["entries"].sort(key=lambda e: e["domain"])
    evidence["generated_at"] = (datetime.datetime.now(datetime.timezone.utc)
                               .replace(microsecond=0).isoformat())
    evidence["methodology"] = evidence["methodology"] + (
        " Entries added %s come from a different route and say so in `provenance`: a "
        "stratified random-sample audit of our OWN published list (see audit/README.md), "
        "where the evidence is live DNS-over-HTTPS (MX/A/TXT/_dmarc) plus an HTTP root "
        "fetch recorded at audit time. Only verdicts at confidence 'high' -- meaning both "
        "a live web root naming a real-world organisation AND mail hosting that is paid "
        "per mailbox or an enterprise gateway -- were promoted here and removed from the "
        "list. The audit's medium-confidence findings are deliberately NOT in this file "
        "and are NOT excluded from the list; they are reported as an upper band instead."
        % args.stamp)
    with open(ev_path, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print("appended to %s (%d entries total)" % (ev_path, len(evidence["entries"])))


if __name__ == "__main__":
    main()
