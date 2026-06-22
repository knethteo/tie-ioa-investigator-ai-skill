# TIE IoA investigation — {IOA_NAME}

**Report generated:** {YYYY-MM-DD}
**Analyst:** {ANALYST}
**Source:** {CSV filename and row count, or "pasted incident description"}
**Incidents analysed:** {N distinct incidents from the latest {LIMIT} alerts}

> {Truncation notice — include verbatim when applicable: "The export contained
> {TOTAL} alerts. Per the standard procedure, only the latest {LIMIT} were
> analysed; {TOTAL-LIMIT} older alerts were not reviewed."}

---

## Incident {i}: {short label, e.g. "DCSync from MSOL_… against APJLAB-DC"}

**Alert details**

| Field | Value |
| ----- | ----- |
| IoA | {IoA name} |
| Acting account | {username / SID} |
| Source | {hostname (IP), or "Unknown"} |
| Destination (DC) | {hostname (IP)} |
| First / last seen | {timestamps} |
| Occurrences in window | {count} |

### What this alert means

{2-4 sentences in the house style: explain the IoA detection logic — which
events TIE correlates, what the alert fires on, and what a real attack would
look like. Draw from the bundled reference guide section and docs.tenable.com.}

### Likelihood assessment

**Verdict: likely a {False Positive | False Negative | True Positive}**
**Confidence: {1-10}/10**

{1-3 numbered signals that explain the verdict. Each signal ties a concrete
observation from the alert data (source, account, destination, frequency) to a
known legitimate pattern or to a genuine attack indicator from the reference
guide.}

1. {signal}
2. {signal}
3. {signal}

### Top investigation steps

{2-4 concrete, ordered checks the customer can run to confirm the verdict in
either direction. Be specific about events, accounts, time windows, and tools.}

1. {step}
2. {step}
3. {step}

### Recommended action

{One line: e.g. "Whitelist {source/account} in the {IoA} indicator options to
suppress recurring false positives," or "Escalate — treat as a live incident
and isolate {host}."}

---

## Summary

| Incident | IoA | Verdict | Confidence |
| -------- | --- | ------- | ---------- |
| 1 | {IoA} | {verdict} | {n}/10 |
| 2 | {IoA} | {verdict} | {n}/10 |

**Sources:** Tenable Identity Exposure — Indicators of Attack Reference Guide
(bundled); Tenable docs (https://docs.tenable.com/identity-exposure.htm).
