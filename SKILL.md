---
name: tie-ioa-investigation
description: >-
  Investigate a Tenable Identity Exposure (TIE) Indicator of Attack (IoA) alert
  to decide whether it is a false positive, false negative, or true positive,
  with a 1-10 confidence score. Use when the user uploads a TIE IoA CSV export
  (comma OR semicolon delimited) or pastes one or more attack/incident
  descriptions from the TIE console and asks to triage, investigate, or decide
  whether an IoA alert (DCSync, NTDS Extraction, Golden Ticket, Kerberoasting,
  DCShadow, Zerologon, PetitPotam, Password Spraying, etc.) is legitimate or a
  real attack. Triggers on phrases like "investigate this IoA", "is this alert
  a false positive", "triage these TIE attacks", "whitelist this alert".
---

# TIE IoA Investigation

Produce a **repeatable** false-positive / false-negative determination for
Tenable Identity Exposure Indicators of Attack, with a confidence score and
investigation steps. Output is a Markdown report with a fixed title and header.

## Reference guide (required)

Before any analysis, you need the *Tenable Identity Exposure — Indicators of
Attack Reference Guide*. It is available behind login at:

> https://www.tenable.com/downloads/identity-exposure#documentation

If the user has not already provided the guide, prompt them:

> "To investigate IoA alerts I need the Tenable Identity Exposure — Indicators
> of Attack Reference Guide. Please download it from
> https://www.tenable.com/downloads/identity-exposure#documentation
> (login required) and give me the path. **Markdown (.md) is preferred**;
> PDF (.pdf) is also accepted."

Once the user supplies a path, build the section index immediately:

```
python3 scripts/build_ioa_index.py "<path-to-guide>" \
  --output reference/ioa-section-index.md
```

The script auto-detects delimiter (MD or PDF), locates every IoA section, and
writes `reference/ioa-section-index.md`. If the script reports any IoAs as
"not found", note them and grep the guide file manually to locate those
sections. The script prints a summary to stderr (e.g. "Found 17/17 IoA
sections").

A user-supplied guide at any path takes precedence. The bundled
`reference/ioa-reference-guide.md` (if present) may be used as a fallback but
is an internal copy not intended for customer environments.

## Inputs (two modes)

**Mode A — CSV export.** The user provides a path to a TIE IoA CSV. It may be
comma- OR semicolon-delimited and may carry a UTF-8 BOM. Columns are typically:
`Date, Attack Vector, Source Hostname, Source IP, Source Type, Destination
Hostname, Destination IP, Destination Type`.

**Mode B — pasted description(s).** The user pastes one or more attack-vector /
incident descriptions copied from the TIE console.

If the user has not made the mode clear, ask which one. In Mode B, if they have
**not** already pasted the incident description, prompt them:
> "Paste the incident description(s) from the TIE console (the Attack Vector /
> 'What happened' text). Include the source and destination if shown."

## Workflow

### 1. Parse and truncate (analyse only the latest 20)

**Mode A:** run the bundled parser. It auto-detects the delimiter, strips the
BOM, sorts by Date descending, keeps only the latest 20 rows, prints a
truncation notice, and groups duplicate alerts into distinct incidents:

```
python3 scripts/parse_ioa_csv.py "<path-to-csv>" --limit 20
```

Add `--json` for machine-readable output if you want to post-process. **You must
tell the user when truncation happened**, e.g. "The export had 85,317 alerts; I
analysed only the latest 20 per the standard procedure — 85,297 older alerts
were not reviewed." Never analyse more than the latest 20.

**Mode B:** treat each pasted description as one incident. If more than 20 are
pasted, analyse the latest/first 20 and state that you truncated.

### 2. Identify the IoA for each distinct incident

Map each incident to its IoA from the attack-vector text (DCSync, NTDS
Extraction, Golden Ticket, Kerberoasting, DCShadow, DNSAdmins, Zerologon,
PetitPotam, Password Guessing/Spraying, SAM Name Impersonation, Suspicious DC
Password Change, Domain Backup Key Extraction, Enumeration of Local
Administrators, Massive Computers Reconnaissance, Unauthenticated Kerberoasting,
OS Credential Dumping).

### 3. Gather IoA knowledge (reference guide first, then web)

Use the guide and index produced during the setup step above.

**Guide formats — recognise both:**

- **Markdown (.md)** — preferred. Read directly. If the user supplied a path,
  use that; fall back to `reference/ioa-reference-guide.md` if present.
- **PDF (.pdf)** — extract text before grepping:
  ```
  python3 -c "import pdfplumber,sys; print('\n'.join((p.extract_text() or '') for p in pdfplumber.open(sys.argv[1]).pages))" "<path-to-guide.pdf>" > /tmp/ioa-guide.txt
  ```
  (If `pdfplumber` is unavailable, use the `pdf` skill or `pdftotext`.)

Then:

1. Open `reference/ioa-section-index.md` (built by `build_ioa_index.py` during
   setup) to find the section line number and the common false-positive sources
   for that IoA.
2. Read the matching section in the guide (Markdown or `/tmp/ioa-guide.txt`).
   Grep the IoA name if line numbers have drifted. Focus on **How the IoA
   works**, the detection **Events**, and the **Options** table (whitelist
   controls, aggressive mode, defer time) — these drive the verdict.
3. Supplement with a live check of https://docs.tenable.com/identity-exposure.htm
   (web search) for anything ambiguous or newer than the guide. If no network,
   proceed with the available guide and say so.

### 4. Decide verdict + confidence (1-10)

Weigh the observed alert data against the legitimate patterns and genuine-attack
indicators for that IoA. Use this rubric:

- **False Positive** — the source/account/destination matches a known-good
  pattern (sync account such as `MSOL_*`/`ENTRAIDSYNC`, EDR/AV like SentinelOne
  creating shadow copies, backup tooling, scanners, legitimate admin tools), or
  a whitelist option clearly applies, or the detection gap has a benign
  explanation (e.g. missing 4768/4770 on an unmonitored DC, "Data not available"
  interval, defer time set below max ticket lifetime).
- **True Positive** — source/account/destination and behaviour are consistent
  with the attack and have no benign explanation (e.g. Golden Ticket from a
  workstation/jump box impersonating a privileged identity with no preceding
  legitimate TGT and a prior krbtgt exposure).
- **False Negative** — evidence suggests a real attack that the alert
  *under-represents or that TIE would miss* (e.g. an attack launched from an
  unmonitored DC, source shown as "Unknown" masking a real origin, or activity
  that a whitelist/aggressive-mode-off setting would suppress). Flag when a
  benign-looking alert may be hiding genuine malicious activity.

Confidence scale: **1-3** weak/insufficient evidence; **4-6** plausible but
needs the investigation steps to confirm; **7-8** strong signals, verdict likely
correct; **9-10** unambiguous. Be honest — reserve 9-10 for clear-cut cases.

### 5. Write the report

Use `templates/investigation-report-template.md`. Keep the **fixed title and
header** so output is repeatable:

- Title: `# TIE IoA investigation — {IoA name}` (or `— multiple IoAs` if mixed).
- Always include the metadata header (date, analyst, source, incidents analysed)
  and the truncation note when applicable.
- One section per distinct incident: alert details table, "What this alert
  means", "Likelihood assessment" (verdict + confidence + numbered signals),
  "Top investigation steps", "Recommended action".
- End with a Summary table (incident / IoA / verdict / confidence) and Sources.

Save the report as `TIE-IoA-investigation-{IoA-or-date}.md` in the user's
folder, then present it.

## House style (match the project's existing investigation docs)

- Mirror the language of the Golden Ticket / NTDS reference docs in this project:
  plain, factual, security-analyst tone. Lead "What this alert means" with the
  concrete detection logic (which event IDs TIE correlates and what gap it
  flags).
- Verdict phrased as "**Verdict: likely a False Positive**" etc.
- Limit em dashes; use commas, brackets, or restructure instead.
- Do not invent event IDs, account names, or IPs — use only what is in the alert
  data and the reference guide.

## Notes / edge cases

- "Unknown" source is common and, by itself, is **not** proof of attack
  (TIE's "Allow unknown source" defaults to True). Weigh it with the account and
  destination.
- A single recurring attack vector across many rows is one incident, not many —
  the parser already groups these; report it once with an occurrence count.
- If the IoA is not in the bundled guide, say so and rely on docs.tenable.com.
