#!/usr/bin/env python3
"""
parse_ioa_csv.py — Normalize and triage a Tenable Identity Exposure (TIE)
Indicators of Attack (IoA) export for investigation.

Handles:
  - Comma OR semicolon delimited files (auto-detected)
  - UTF-8 BOM
  - Quoted fields whose values contain the delimiter (e.g. "10.1.1.4, 10.2.2.4")
  - Markdown formatting inside the Attack Vector text (backticks, **bold**)

Behaviour:
  - Sorts all rows by Date descending (most recent first)
  - Keeps only the latest N rows (default 20) for analysis and PRINTS A
    TRUNCATION NOTICE when the file contained more than N rows
  - Groups the analysed rows by normalized Attack Vector so the investigator
    sees distinct incidents rather than thousands of duplicates

Usage:
  python3 parse_ioa_csv.py <path-to-csv> [--limit 20] [--json]
"""

import argparse
import csv
import io
import json
import re
import sys
from collections import OrderedDict


def detect_delimiter(sample: str) -> str:
    """Prefer csv.Sniffer; fall back to a simple count of ; vs , on the header."""
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,")
        return dialect.delimiter
    except csv.Error:
        header = sample.splitlines()[0] if sample.splitlines() else ""
        return ";" if header.count(";") >= header.count(",") else ","


def clean_markdown(text: str) -> str:
    """Strip the markdown TIE puts in the Attack Vector field for grouping."""
    if text is None:
        return ""
    t = text.replace("`", "").replace("**", "")
    t = re.sub(r"\s+", " ", t).strip()
    return t


def vector_key(text: str) -> str:
    """
    Build a grouping key that ignores instance-specific values so identical
    attack patterns collapse together. We blank out IPs and obvious GUID/SID
    style tokens so 'same attack, different timestamp' groups as one.
    """
    t = clean_markdown(text).lower()
    t = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", t)
    t = re.sub(r"s-1-\d-(?:\d+-)*\d+", "<sid>", t)
    return t


def load_rows(path: str):
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8-sig", errors="replace")  # utf-8-sig strips BOM
    delim = detect_delimiter(text[:4096])
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    rows = [dict(r) for r in reader]
    # Normalize header keys (strip whitespace / case-insensitive lookup helper)
    return rows, delim, (reader.fieldnames or [])


def get(row, *names):
    """Case-insensitive, whitespace-tolerant column lookup."""
    lower = {(k or "").strip().lower(): v for k, v in row.items()}
    for n in names:
        v = lower.get(n.strip().lower())
        if v is not None:
            return v
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    try:
        rows, delim, fields = load_rows(args.csv_path)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.csv_path}", file=sys.stderr)
        sys.exit(1)

    total = len(rows)

    # Sort by Date descending. Dates are ISO-8601 (sortable as strings); fall
    # back to original order for any unpar. missing dates sink to the bottom.
    def date_key(r):
        return get(r, "Date", "date") or ""

    rows.sort(key=date_key, reverse=True)

    truncated = total > args.limit
    analysed = rows[: args.limit]

    # Group analysed rows by normalized attack vector
    groups = OrderedDict()
    for r in analysed:
        av = get(r, "Attack Vector", "AttackVector", "Vector", "Description")
        key = vector_key(av)
        g = groups.setdefault(
            key,
            {
                "attack_vector": clean_markdown(av),
                "count": 0,
                "first_seen": None,
                "last_seen": None,
                "source_hostnames": set(),
                "source_ips": set(),
                "destinations": set(),
            },
        )
        g["count"] += 1
        d = date_key(r)
        if d:
            g["last_seen"] = max(g["last_seen"], d) if g["last_seen"] else d
            g["first_seen"] = min(g["first_seen"], d) if g["first_seen"] else d
        sh = get(r, "Source Hostname", "SourceHostname")
        si = get(r, "Source IP", "SourceIP")
        dh = get(r, "Destination Hostname", "DestinationHostname")
        if sh:
            g["source_hostnames"].add(sh)
        if si:
            g["source_ips"].add(si)
        if dh:
            g["destinations"].add(dh)

    # Serialize sets for output
    out_groups = []
    for g in groups.values():
        out_groups.append(
            {
                "attack_vector": g["attack_vector"],
                "occurrences_in_window": g["count"],
                "first_seen": g["first_seen"],
                "last_seen": g["last_seen"],
                "source_hostnames": sorted(g["source_hostnames"]),
                "source_ips": sorted(g["source_ips"]),
                "destinations": sorted(g["destinations"]),
            }
        )

    summary = {
        "file": args.csv_path,
        "delimiter": delim,
        "columns": fields,
        "total_rows": total,
        "analysed_rows": len(analysed),
        "limit": args.limit,
        "truncated": truncated,
        "distinct_incidents": len(out_groups),
        "incidents": out_groups,
    }

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return

    # Human-readable summary
    print("=" * 72)
    print("TIE IoA export — parsed summary")
    print("=" * 72)
    print(f"File              : {args.csv_path}")
    print(f"Delimiter detected: '{delim}'")
    print(f"Total rows in file: {total}")
    if truncated:
        print(
            f"\n>>> TRUNCATED: analysing only the latest {args.limit} rows "
            f"(of {total}). {total - args.limit} older rows were not analysed."
        )
    else:
        print(f"\nAnalysing all {total} rows (under the {args.limit}-row limit).")
    print(f"Distinct attack patterns in window: {len(out_groups)}\n")

    for i, g in enumerate(out_groups, 1):
        print(f"--- Incident {i} ---")
        print(f"Occurrences (in window): {g['occurrences_in_window']}")
        print(f"First seen: {g['first_seen']}   Last seen: {g['last_seen']}")
        print(f"Source hostname(s): {', '.join(g['source_hostnames']) or 'n/a'}")
        print(f"Source IP(s)      : {', '.join(g['source_ips']) or 'n/a'}")
        print(f"Destination(s)    : {', '.join(g['destinations']) or 'n/a'}")
        print(f"Attack vector     : {g['attack_vector']}\n")


if __name__ == "__main__":
    main()
