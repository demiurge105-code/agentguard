# External Gateway Checkpoints — Format v1

## Purpose and security boundary

An external checkpoint records a verifiable summary of the Gateway operation event chains at one point in time. It is intended to make later rewriting or deletion of previously recorded SQLite history detectable when the attacker cannot also rewrite the independently retained checkpoint.

A checkpoint is not a signature, proof of authorship, or immutable storage. SHA-256 provides integrity linkage, not publisher authentication. If an attacker can rewrite both the SQLite database and every external checkpoint copy, this mechanism cannot detect the rewrite. A checkpoint also says nothing about events created after its publication until a later checkpoint is published.

The checkpoint contains no transaction payloads, recipient addresses, amounts, policy contents, or event reasons.

## Canonical encoding and hashes

All hashes use SHA-256 and lowercase hexadecimal output.

Canonical JSON is UTF-8 encoded JSON with:
- object keys sorted lexicographically;
- compact separators `(",", ":")`;
- non-ASCII characters emitted directly (not escaped);
- no floating-point values anywhere in the document;
- no duplicate object keys when parsing an imported document.

The checkpoint hash is:

```text
SHA256(
  "agentguard.gateway-checkpoint.v1:" ||
  canonical_json(checkpoint_without_checkpoint_hash)
)
```

The `checkpoint_hash` field is excluded from the hashed object. Hash strings are exactly 64 lowercase hexadecimal characters.

An operation reference is:

```text
"sha256:" || SHA256(
  "agentguard.gateway-checkpoint-operation-ref.v1:" ||
  UTF8(operation_id)
)
```

The raw operation UUID is never included in the exported document.

The first checkpoint uses 64 zeroes as `previous_checkpoint_hash` and has `sequence = 1`. Each later checkpoint must reference the immediately previous checkpoint hash and increment its sequence by exactly one.

## Document shape

```json
{
  "format_version": 1,
  "installation_id": "7f3a2c91-...",
  "checkpoint_id": "a UUID",
  "sequence": 1,
  "created_at": "2026-11-16T10:00:00+00:00",
  "hash_algorithm": "sha256",
  "event_chain_version": 1,
  "operation_count": 2,
  "operations": [
    {
      "operation_ref": "sha256:...",
      "event_count": 4,
      "head_hash": "..."
    },
    {
      "operation_ref": "sha256:...",
      "event_count": 7,
      "head_hash": "..."
    }
  ],
  "previous_checkpoint_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "checkpoint_hash": "..."
}
```

The example is illustrative; the UUIDs and hashes are not valid checkpoint material.

Required validation rules:
- `format_version` is integer 1; `hash_algorithm` is exactly `sha256`; `event_chain_version` is integer 1.
- `installation_id` and `checkpoint_id` are canonical lowercase UUID strings.
- `sequence` is a positive integer; `operation_count` is a non-negative integer equal to the number of entries in `operations`.
- `created_at` is a timezone-aware ISO 8601 timestamp.
- Each `operation_ref` is unique and matches `sha256:[0-9a-f]{64}`.
- Each `event_count` is a non-negative integer. Each `head_hash` is 64 lowercase hexadecimal characters.
- Entries are sorted by `operation_ref` in ascending lexical order.
- `previous_checkpoint_hash` and `checkpoint_hash` are 64 lowercase hexadecimal characters.
- Unknown fields, missing fields, invalid types, booleans where integers are required, and floating-point values are rejected.

## Export snapshot semantics

Export must run inside one SQLite read transaction. The first read establishes the SQLite snapshot; the installation ID, operations, event counts, and event rows must all be read from that same snapshot. This prevents concurrent Gateway writes from producing a checkpoint assembled from different database states.

For each operation:
1. Read its event rows ordered by `event_id`.
2. Set `event_count` to the number of rows in that snapshot.
3. Set `head_hash` to the `event_hash` of the final row.
4. If there are no events, use the event-chain genesis hash (64 zeroes).

The exporter must reject an operation whose stored event count/head does not agree with the rows visible in the snapshot, or whose event chain fails local verification. It must not silently export a malformed or internally inconsistent chain.

The operation list includes every Gateway operation present in the snapshot. A newly created operation after this checkpoint is allowed during later verification; its absence from an older checkpoint is not an error.

## Verification against a local database

Verification first validates the imported document's schema, canonical values, and checkpoint hash. It then checks that `installation_id` matches the local database identity. A missing local identity returns `INSTALLATION_ID_MISSING`; a different identity returns `INSTALLATION_ID_MISMATCH`.

For every operation recorded in the checkpoint:
1. The corresponding local operation must still exist.
2. Its current event chain must pass the existing full local event-chain verifier.
3. The local chain must contain at least `event_count` events.
4. If `event_count > 0`, the event hash at position `event_count` (1-based, ordered by `event_id`) must equal the checkpoint's `head_hash`. If `event_count = 0`, the checkpoint head must equal the genesis hash.

This deliberately does not compare the checkpoint head with the current local head: events appended after checkpoint publication are valid. The verifier detects deletion or modification of a previously checkpointed prefix while allowing later append-only activity.

Operations created after checkpoint publication are allowed. An operation recorded in the checkpoint but missing locally is a mismatch.

## Checkpoint chain verification

A checkpoint can be checked for internal hash validity without its predecessor, but continuity can only be established when the preceding checkpoint document is available.

When a predecessor is supplied, require:
- the same `installation_id`;
- `sequence = predecessor.sequence + 1`;
- `previous_checkpoint_hash = predecessor.checkpoint_hash`;
- the predecessor's own checkpoint hash to be valid.

Without a predecessor, only the genesis checkpoint (sequence 1 and all-zero previous hash) can be accepted as a chain root. A later checkpoint must not be treated as a verified root merely because its own hash is valid.

## Failure codes

The v1 verifier should return stable machine-readable reasons, including:
- `INSTALLATION_ID_MISSING`
- `INSTALLATION_ID_MISMATCH`
- `CHECKPOINT_INVALID`
- `CHECKPOINT_MISMATCH`

More specific internal mismatch reasons may be exposed where useful (for example, missing operation, event prefix mismatch, or broken checkpoint continuity), while preserving the stable top-level failure category.

## Publication guidance

The first implementation should export a local JSON document and verify a supplied JSON document. It must not store GitHub credentials or publish checkpoints automatically. Publication to an independently controlled repository or storage account is a separate integration step and must be explicit.
