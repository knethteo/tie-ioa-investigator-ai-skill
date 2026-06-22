---
name: reference-directory-contents
description: What lives in the reference/ directory and its availability to customers
metadata:
  type: project
---

The `reference/` directory contains two files:

- `ioa-section-index.md` — index of IOA sections, used for navigation/lookup
- `ioa-reference-guide.md` — attack reference guide; **not generally available to customers**

**Why:** The attack reference guide contains sensitive/internal content that should not be shipped to customers. The index is a lightweight companion used to orient the skill.

**How to apply:** When building prompts or packaging the skill for customer delivery, do not include `ioa-reference-guide.md`. The index may be referenced but the full guide should remain internal.
