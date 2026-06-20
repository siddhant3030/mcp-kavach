# The tokenization vault

## The problem it solves

Masking destroys identity. If a tool result has five rows about the same
person, `[MASKED:PERSON_NAME]` turns them into five indistinguishable blanks —
the model can no longer count distinct people, join rows, or summarize
"everything about beneficiary X". Masking is safe for lookups but useless for
analysis.

The vault fixes this with the **coat-check pattern**: hand in a coat, get
ticket #7; hand in the same coat again, get the *same* ticket; only the
coat-check (you, locally) can swap tickets back for coats. Concretely:

- The same value always becomes the same stable token within a scope:
  `Lakshmi Devi` → `[PERSON_NAME_1]`, every time, in every row.
- A different value gets the next number: `[PERSON_NAME_2]`.
- The model sees only tickets. It can dedupe, join, and reason about
  "`[PERSON_NAME_1]`'s three visits" without ever seeing a name.
- At a **trusted sink** — your terminal, your report generator, anything that
  runs on your machine after the model is done — `virelia rehydrate` swaps the
  tickets back for the real values.

## Enabling it

Install the extra (the vault encrypts values with Fernet from the
`cryptography` package):

```bash
pip install 'virelia[vault]'
```

Use the `tokenize` action in your policy:

```yaml
rules:
  - id: names
    entities: [PERSON_NAME]
    action: tokenize
```

Then give the engine a vault — via the CLI:

```bash
virelia scan "Lakshmi Devi called Lakshmi Devi" --policy my.yaml --vault
virelia proxy --config mcp.json --policy my.yaml --vault
```

or in Python:

```python
from virelia import Engine, Vault, load_policy

engine = Engine(load_policy("my.yaml"), vault=Vault())
```

`--vault` with no path uses the default location,
`$VIRELIA_DATA_DIR/vault.db` (usually `~/.local/share/virelia/vault.db`).

**Fail-safe:** if a policy says `tokenize` but no vault is configured (or the
extra isn't installed), virelia logs a warning and falls back to plain
`mask` — values are still hidden, you just lose consistency and reversibility.

## Getting the values back (the trusted sink)

```bash
# from a file
virelia rehydrate report.md > report-with-names.md
# or from stdin
echo "follow up with [PERSON_NAME_1] at [PHONE_1]" | virelia rehydrate
```

Or in Python — works on strings or whole nested payloads:

```python
from virelia.vault import rehydrate
original = rehydrate(model_output)
```

Unknown tokens pass through untouched, so rehydrating text that was never
tokenized is harmless.

## Scopes

A scope is one coat-check counter. Token numbers count up per scope, and
rehydration only sees its own scope's mappings — `[PERSON_NAME_1]` in scope
`session-a` and scope `session-b` can be two different people. By default
everything shares one scope (`default`) per vault file; pass `--scope` on the
CLI or `Vault(scope="...")` in Python to isolate sessions or projects.

## What's actually stored, and how

One SQLite file, mode `0600`, with one row per (scope, entity type, value):

| column | contents |
|--------|----------|
| `scope` | the coat-check counter this row belongs to |
| `entity_type` | normalized token label (`PERSON_NAME`, `PHONE`, ...) |
| `value_hmac` | salted HMAC-SHA256 of the value — how lookups find it without storing plaintext keys (same construction as the audit log) |
| `encrypted_value` | the value, Fernet-encrypted with a locally-generated key |
| `token_id` | the number in `[ENTITY_N]` |
| `created_at` | first time this value was seen |

The key lives next to the database (`vault.key`, also `0600`) and is generated
on first use. The HMAC salt is derived from that key, so the database alone —
without the key file — reveals neither values nor even whether a given value
is present.

## Security notes — read this

- **The vault file plus its key *are* your PII.** Anyone with both can
  rehydrate every token ever issued. Protect `~/.local/share/virelia/` like a
  password store: don't commit it, don't sync it to shared drives, don't ship
  it in backups that others can read.
- Tokens leak *linkage* by design: the model (and its provider) can tell that
  five rows concern the same person, and roughly how many distinct people
  there are. If even that is too much for an entity, use `redact` or `block` —
  in severity ordering they outrank `tokenize` precisely so they can never be
  overridden by it.
- Deleting `vault.db` (or just a scope's rows) makes the corresponding tokens
  permanently meaningless — that's your "burn the coat-check" option.
- Rehydrate only at genuinely trusted sinks. If you pipe rehydrated output
  back into a model prompt, you've undone the whole exercise.
