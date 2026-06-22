# TIE IoA Investigator

A Claude Code skill that triages Tenable Identity Exposure (TIE) Indicators of Attack (IoA) alerts, determining whether each is a **false positive**, **true positive**, or **false negative** with a 1–10 confidence score.

## What it does

- Parses TIE IoA CSV exports (comma or semicolon delimited, UTF-8 BOM safe) or accepts pasted incident descriptions from the TIE console
- Automatically limits analysis to the latest 20 alerts and groups duplicate attack patterns into distinct incidents
- Maps each incident to its IoA type (DCSync, Golden Ticket, NTDS Extraction, Kerberoasting, and 13 others)
- Cross-references the Tenable Identity Exposure IoA Reference Guide and live Tenable documentation
- Produces a structured Markdown investigation report with verdict, confidence score, supporting signals, investigation steps, and whitelist recommendations

## Supported IoAs

DCSync, NTDS Extraction, Golden Ticket, Kerberoasting, DCShadow, DNSAdmins Exploitation, Zerologon, PetitPotam, Password Guessing/Spraying, SAM Name Impersonation, Suspicious DC Password Change, Domain Backup Key Extraction, Enumeration of Local Administrators, Massive Computers Reconnaissance, Unauthenticated Kerberoasting, OS Credential Dumping: LSASS Memory.

## Before you start

The skill requires the **Tenable Identity Exposure — Indicators of Attack Reference Guide** to look up detection logic, whitelist options, and false-positive patterns for each IoA. Have it ready before invoking the skill.

1. Log in to the Tenable downloads portal: https://www.tenable.com/downloads/identity-exposure#documentation
2. Download the reference guide. **Markdown (`.md`) is preferred**; PDF (`.pdf`) is also accepted.
3. Note the file path — the skill will ask for it on first use and will automatically build a section index from it.

## Requirements

- Claude Code
- Python 3 (for the bundled scripts)
- `pdfplumber` (optional — only needed if supplying the reference guide as a PDF): `pip install pdfplumber`

## Scripts

| Script | Purpose |
| ------ | ------- |
| `scripts/parse_ioa_csv.py` | Normalizes a TIE IoA CSV export: auto-detects comma/semicolon delimiter, strips UTF-8 BOM, sorts by date descending, limits to the latest 20 rows, and groups duplicate attack patterns into distinct incidents. Supports `--json` for machine-readable output. |
| `scripts/build_ioa_index.py` | Builds a section index from the reference guide (MD or PDF). Locates each IoA section, records its line number, and writes `reference/ioa-section-index.md` so the skill can jump directly to the relevant Options table during analysis. |

## Templates

| File | Purpose |
| ---- | ------- |
| `templates/investigation-report-template.md` | Fixed-structure Markdown template for investigation reports. Defines the required title format, metadata header, per-incident sections (alert details, what the alert means, likelihood assessment, investigation steps, recommended action), and the summary table. The skill fills this template for every investigation to ensure consistent, repeatable output. |

## Usage

Trigger phrases:
- `investigate this IoA`
- `is this alert a false positive`
- `triage these TIE attacks`
- `whitelist this alert`

The skill will ask for the reference guide on first use, build the section index, then prompt for either a CSV export path or a pasted incident description.

## Invocation

```
/tie-ioa-investigation
```

## Output

A Markdown report saved as `TIE-IoA-investigation-{IoA-or-date}.md` containing:
- Alert details table per incident
- What the alert means (detection logic, relevant event IDs)
- Likelihood assessment (verdict + confidence + numbered signals)
- Top investigation steps
- Recommended action (whitelist configuration or escalation)
- Summary table across all incidents

## License

MIT — see [LICENSE](LICENSE).
