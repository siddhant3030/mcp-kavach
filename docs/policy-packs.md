# Regulation policy packs

> **DRAFT — conservative defaults, not legal advice.** These packs have not
> been through a requirement-by-requirement legal mapping. That work is tracked
> in issue [#15](https://github.com/siddhant3030/virelia/issues/15) for DPDP
> and will get its own issues for GDPR and HIPAA. Until then the packs stay
> deliberately strict: when unsure, they mask or block. Using a pack does not
> make a deployment compliant with any regulation.

Start with a pack instead of writing YAML from scratch:

```bash
virelia proxy --config upstreams.json --policy dpdp   # or gdpr, hipaa-lite
```

## What each pack does, entity by entity

| Entity | `dpdp` | `gdpr` | `hipaa-lite` |
|---|---|---|---|
| AWS_ACCESS_KEY, GITHUB_TOKEN, JWT (credentials) | block | block | block (whole result withheld) |
| AADHAAR | block | block | block |
| PAN | block | block | block |
| GOVT_ID | block | block | block |
| CREDIT_CARD | block | block | block |
| BANK_ACCOUNT | block | block | block |
| PERSON_NAME | mask | mask | block |
| EMAIL | mask | mask | block |
| PHONE | mask | mask | block |
| ADDRESS | redact | redact | block |
| DOB | redact | redact | block |
| IP_ADDRESS | mask | mask | block |
| IFSC (bank branch code, not personal) | allow | allow | allow |
| anything else detected (fail-closed default) | mask | mask | block |
| minimum detection confidence | 0.4 | 0.4 | 0.3 |

Action meanings are in the [policy schema reference](policy-schema.md):
`mask` replaces the value with `[MASKED:ENTITY_TYPE]`, `redact` with
`[REDACTED]`, `block` refuses the field (or the whole result with
`scope: result`).

## dpdp — India

For organizations in India handling personal data under the Digital Personal
Data Protection Act — NGOs, startups, anyone whose tool results may carry
beneficiary or customer records. Government identifiers (Aadhaar, PAN) and
financial numbers are blocked outright and never reach the model. Names,
emails, phones, and IPs are masked; addresses and birth dates are removed.
It is a tightened version of `ngo-default`: contact info gets a full mask
instead of a partial one, and IP addresses are masked instead of allowed.

## gdpr — EU

For teams handling EU residents' data. The GDPR's idea of "personal data" is
broad — anything that can identify a person directly or indirectly — so this
pack masks every personal-data entity virelia detects, including IP addresses
(which EU courts treat as personal data). Government IDs and financial
identifiers are blocked outright. Anything detected that no rule covers is
masked.

## hipaa-lite — health context

For tools that touch patient or health-program data. It blocks the
identifiers from the HIPAA Safe Harbor de-identification list that virelia can
currently detect: names, phones, emails, IP addresses, account numbers,
government IDs, dates of birth, and addresses. It is the strictest pack:
anything detected that no rule covers is **blocked**, and the confidence bar
is lower so borderline detections still count. It is called "lite" because
the full Safe Harbor list (all date elements, medical record numbers, device
identifiers, biometrics, photos, …) needs NER and date handling virelia does
not have yet.

## Known limits (all three packs)

- `PERSON_NAME`, `ADDRESS`, `DOB`, `BANK_ACCOUNT`, and `GOVT_ID` come from
  column-name heuristics (Tier 0). They fire when a JSON key looks like
  `name`, `address`, `dob`, … — a name typed inside free text is **not**
  caught yet. The NER tier (issue #7) closes this gap.
- The packs only cover what the detectors can see. New India identifiers
  (GSTIN, UPI, passport) and date handling are on the roadmap; the packs'
  fail-closed defaults are the safety net until then.
