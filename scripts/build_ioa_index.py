#!/usr/bin/env python3
"""
build_ioa_index.py — Build a TIE IoA section index from a reference guide.

Accepts:
  - A Markdown file (.md) — the preferred format; produced by Tenable or by
    converting the official PDF.
  - A PDF file (.pdf) — the original Tenable document; requires pdfplumber.

Outputs a Markdown table compatible with reference/ioa-section-index.md.

Usage:
  python3 build_ioa_index.py <path-to-guide.md>
  python3 build_ioa_index.py <path-to-guide.pdf>
  python3 build_ioa_index.py <path> --output reference/ioa-section-index.md
"""

import argparse
import re
import sys

IOA_NAMES = [
    "OS Credential Dumping: LSASS Memory",
    "Suspicious DC Password Change",
    "DCShadow",
    "DCSync",
    "DNSAdmins Exploitation",
    "Domain Backup Key Extraction",
    "Enumeration of Local Administrators",
    "Golden Ticket",
    "Kerberoasting",
    "Massive Computers Reconnaissance",
    "NTDS Extraction",
    "Password Guessing",
    "Password Spraying",
    "PetitPotam",
    "SAM Name Impersonation",
    "Unauthenticated Kerberoasting",
    "Zerologon Exploitation",
]

FP_SOURCES = {
    "OS Credential Dumping: LSASS Memory": "EDR/AV agents, legitimate admin tools in deny list, aggressive mode",
    "Suspicious DC Password Change": 'Legitimate password rotation, admin tools (AdMod/Netdom), "Data not available" interval',
    "DCShadow": "Legitimate DC promotion/replication, admin activity",
    "DCSync": "Azure AD / Entra Connect sync accounts (MSOL_*, ENTRAIDSYNC), defer-time whitelisting",
    "DNSAdmins Exploitation": "Legitimate DLL plug-ins (allowed DLL paths), DNS admin maintenance",
    "Domain Backup Key Extraction": "Backup tooling, legitimate DPAPI maintenance",
    "Enumeration of Local Administrators": "Inventory/asset tools, EDR, vulnerability scanners",
    "Golden Ticket": "Long-running service/sync accounts, missing 4768/4770 on unmonitored DC, defer time vs. ticket lifetime",
    "Kerberoasting": "Vulnerability scanners, legitimate service-ticket requests, security tools",
    "Massive Computers Reconnaissance": "Asset inventory, scanners, management tools (SCCM, etc.)",
    "NTDS Extraction": "Backup software, EDR/AV creating shadow copies (e.g. SentinelOne), legitimate VSS",
    "Password Guessing": "Misconfigured apps/services with stale credentials, account lockout testing",
    "Password Spraying": "Same as above; legitimate auth retries",
    "PetitPotam": "Legitimate EFSRPC / authentication coercion by management tools",
    "SAM Name Impersonation": "Legitimate computer account renames",
    "Unauthenticated Kerberoasting": "Scanners, accounts with DONT_REQ_PREAUTH set for legitimate reasons",
    "Zerologon Exploitation": "Legitimate Netlogon activity, patched-environment scanner probes",
}


def extract_text_from_pdf(path: str) -> list[str]:
    try:
        import pdfplumber
    except ImportError:
        print(
            "ERROR: pdfplumber is not installed. Run: pip install pdfplumber",
            file=sys.stderr,
        )
        sys.exit(1)
    lines = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            lines.extend(text.splitlines())
    return lines


def read_md(path: str) -> list[str]:
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return fh.read().splitlines()


def normalize_line(line: str) -> str:
    """Strip markdown header markers and collapse whitespace."""
    stripped = re.sub(r"^#+\s*", "", line).strip()
    return re.sub(r"\s+", " ", stripped).lower()


def find_sections(lines: list[str]) -> dict[str, int]:
    """Return {ioa_name: first_line_number} for every IoA found in the text."""
    found = {}
    # Pre-build lookup: normalized name and no-spaces variant -> canonical name
    lookup = {}
    for name in IOA_NAMES:
        lower = name.lower()
        lookup[lower] = name
        lookup[lower.replace(" ", "").replace(":", "")] = name

    for lineno, line in enumerate(lines, start=1):
        norm = normalize_line(line)
        no_space = norm.replace(" ", "").replace(":", "")
        for key, canonical in lookup.items():
            if canonical in found:
                continue
            if norm == key or no_space == key.replace(" ", "").replace(":", ""):
                found[canonical] = lineno
                break

    return found


def build_index(path: str) -> dict[str, int]:
    lower = path.lower()
    if lower.endswith(".pdf"):
        lines = extract_text_from_pdf(path)
    else:
        lines = read_md(path)
    return find_sections(lines)


FOOTER = """
## How to read the Options table for a verdict

The **Options** block for each IoA is the heart of false-positive analysis. The
recurring whitelist controls are:

- **Whitelisted source hostnames / source IPs** — the source is a known-good
  origin (scanner, sync host, backup server). A match here is a strong FP signal.
- **Whitelisted usernames** — the acting account is a known service/sync account.
- **Whitelisted target domain controllers** — the destination DC is expected.
- **Allow unknown source (default True)** — when source is only an IP / "Unknown",
  TIE still raises the alert. An "Unknown" source is *not* itself proof of attack.
- **Aggressive mode** — when enabled, raises more alerts and more false positives.
- **Defer time before sending alerts** (DCSync, Golden Ticket) — too low a value
  relative to the domain's max ticket lifetime causes false positives.
"""


def render_index(sections: dict[str, int], guide_path: str) -> str:
    lines = [
        "# IoA Reference Guide — section index",
        "",
        f"Built from: `{guide_path}`",
        "",
        "Use this to jump to the right section of the reference guide. The line",
        "numbers are approximate anchors; if the file is re-exported, grep for",
        "the IoA name instead. Each section contains: how the attack works, how",
        "the IoA works, detection events, the **Options** table (whitelisting /",
        "aggressive mode — the key false-positive controls), and YARA rules.",
        "",
        "| IoA (alert name)                     | Approx. line | Common false-positive sources to check |",
        "| ------------------------------------ | ------------ | --------------------------------------- |",
    ]
    for name in IOA_NAMES:
        lineno = sections.get(name, "not found")
        fp = FP_SOURCES.get(name, "—")
        lines.append(f"| {name:<36} | {str(lineno):<12} | {fp} |")

    missing = [n for n in IOA_NAMES if n not in sections]
    if missing:
        lines += [
            "",
            "> **Note:** The following IoAs were not detected in the guide —",
            "> they may use different section headings. Grep the guide file",
            "> manually to locate them:",
        ]
        for m in missing:
            lines.append(f"> - {m}")

    lines.append(FOOTER)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("guide_path", help="Path to the reference guide (.md or .pdf)")
    ap.add_argument(
        "--output",
        default=None,
        help="Write index to this file (default: print to stdout)",
    )
    args = ap.parse_args()

    sections = build_index(args.guide_path)
    found_count = len(sections)
    total = len(IOA_NAMES)
    print(
        f"Found {found_count}/{total} IoA sections in {args.guide_path}",
        file=sys.stderr,
    )

    index_md = render_index(sections, args.guide_path)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(index_md)
        print(f"Index written to {args.output}", file=sys.stderr)
    else:
        print(index_md)


if __name__ == "__main__":
    main()
