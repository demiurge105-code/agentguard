# External Gateway Checkpoints — Operator Runbook

This runbook describes how to export, retain, and verify the external Gateway checkpoints implemented by AgentGuard Checkpoint Format v1.

For the format and verification rules, see [External Gateway Checkpoints — Format v1](external-checkpoints.md).

## What a checkpoint does — and does not do

A checkpoint records a hashed summary of Gateway operation event-chain prefixes at a particular point in time. If local SQLite history is later rewritten or truncated, verification can detect the change while the independently retained checkpoint remains trustworthy.

A checkpoint is **not** a database backup, a way to reconstruct deleted event rows, a digital signature, proof of publisher identity, or immutable storage. It cannot protect the system if an attacker can replace both the local database and every external checkpoint copy.

The document omits transaction payloads, recipient addresses, amounts, policy contents, and event reasons. It still contains installation/checkpoint identifiers, timestamps, opaque operation references, event counts, and hashes. Treat it as operational integrity metadata.

## Prerequisites

- AgentGuard API is running and connected to the intended SQLite database.
- You can reach the API base URL.
- You have the owner/admin bearer token configured for that API.
- curl and jq are installed.
- You have an external storage destination outside the database's host or failure domain.

Do not put a real bearer token in this document, a command committed to Git, a screenshot, or an issue comment. Set it in your shell environment through your normal secret-handling process.

## 1. Prepare a local working directory

The examples use Bash:

~~~bash
set -euo pipefail
umask 077
export AGENTGUARD_BASE_URL="http://127.0.0.1:8000"
test -n "$AGENTGUARD_ADMIN_TOKEN"
CHECKPOINT_DIR="$HOME/agentguard-checkpoints"
mkdir -p "$CHECKPOINT_DIR"
chmod 700 "$CHECKPOINT_DIR"
~~~

Change AGENTGUARD_BASE_URL to the actual API URL. Keep the token out of source control and avoid echoing it.

## 2. Export the genesis checkpoint

The first checkpoint is the genesis checkpoint. The export endpoint expects an empty JSON object when no predecessor exists:

~~~bash
curl --fail-with-body --silent --show-error --request POST "$AGENTGUARD_BASE_URL/gateway/checkpoints/export" --header "Authorization: Bearer $AGENTGUARD_ADMIN_TOKEN" --header "Content-Type: application/json" --data '{}' --output "$CHECKPOINT_DIR/checkpoint-000001.json"
~~~

The response body is the checkpoint document itself, returned as application/json. Preserve those exact bytes. Do not parse and re-serialize the checkpoint before verification: the API accepts the document as a string so it can reject duplicate JSON object keys.

Check that the file exists and is non-empty:

~~~bash
test -s "$CHECKPOINT_DIR/checkpoint-000001.json"
~~~

## 3. Store the checkpoint independently

Copy the exported file to storage outside the AgentGuard SQLite database and, preferably, outside the host and account that hold that database.

Suitable operator arrangements include a separately controlled private repository or a separate storage account with access controls and version history. These are operator choices; AgentGuard does not publish checkpoints automatically or manage external storage credentials.

Recommended practices:

- Keep the original exported file unchanged.
- Retain every checkpoint in sequence; do not keep only the newest file.
- Keep more than one copy in independently controlled locations when practical.
- Restrict write access. Anyone who can replace the external copies may undermine the evidence.
- Do not assume that a normal Git repository or cloud folder is immutable merely because it is separate.

## 4. Export the next checkpoint

For every checkpoint after genesis, pass the immediately preceding checkpoint document in the previous_checkpoint_json field. The API expects a JSON string, not a nested checkpoint object.

Using jq --rawfile safely embeds the exact previous file contents as a JSON string:

~~~bash
jq -n --rawfile previous_checkpoint_json "$CHECKPOINT_DIR/checkpoint-000001.json" '{previous_checkpoint_json: $previous_checkpoint_json}' | curl --fail-with-body --silent --show-error --request POST "$AGENTGUARD_BASE_URL/gateway/checkpoints/export" --header "Authorization: Bearer $AGENTGUARD_ADMIN_TOKEN" --header "Content-Type: application/json" --data-binary @- --output "$CHECKPOINT_DIR/checkpoint-000002.json"
~~~

Store checkpoint-000002.json independently as well. Repeat this process for each new checkpoint, always supplying the immediately preceding document. Use a monotonically increasing filename or another unambiguous sequence convention.

If export fails because the local audit history is inconsistent or installation identity is unavailable, do not work around the failure by editing the database or checkpoint JSON. Investigate the local storage/audit state first. Export is designed to fail closed.

## 5. Verify the genesis checkpoint

The verify endpoint expects checkpoint_json to contain the checkpoint document as a string:

~~~bash
jq -n --rawfile checkpoint_json "$CHECKPOINT_DIR/checkpoint-000001.json" '{checkpoint_json: $checkpoint_json}' | curl --fail-with-body --silent --show-error --request POST "$AGENTGUARD_BASE_URL/gateway/checkpoints/verify" --header "Authorization: Bearer $AGENTGUARD_ADMIN_TOKEN" --header "Content-Type: application/json" --data-binary @-
~~~

A successful verification returns a JSON result with valid=true, reason_code=null, the checkpoint sequence, operation count, and checkpoint hash.

## 6. Verify subsequent checkpoints in order

A non-genesis checkpoint must be verified with its immediate predecessor. For checkpoint 2:

~~~bash
jq -n --rawfile checkpoint_json "$CHECKPOINT_DIR/checkpoint-000002.json" --rawfile previous_checkpoint_json "$CHECKPOINT_DIR/checkpoint-000001.json" '{checkpoint_json: $checkpoint_json, previous_checkpoint_json: $previous_checkpoint_json}' | curl --fail-with-body --silent --show-error --request POST "$AGENTGUARD_BASE_URL/gateway/checkpoints/verify" --header "Authorization: Bearer $AGENTGUARD_ADMIN_TOKEN" --header "Content-Type: application/json" --data-binary @-
~~~

For checkpoint 3, supply checkpoint 2 as its predecessor; for checkpoint 4, supply checkpoint 3, and so on.

**Verify the retained sequence from genesis forward.** The endpoint accepts one predecessor document at a time. Verifying checkpoint N against N-1 checks that direct link and the supplied predecessor's own document hash; it does not recursively load every earlier file. To establish the complete retained sequence, verify checkpoint 1 as the root, then checkpoint 2 with checkpoint 1, then checkpoint 3 with checkpoint 2, continuing in order. Keep all documents.

## 7. Understand verification results

The verification endpoint can return valid=false as a normal JSON result. A false result is not a successful integrity check.

| Result | Meaning | Operator response |
|---|---|---|
| valid=true | The checkpoint document, installation identity, predecessor link (when supplied), local event chains, and checkpointed event prefixes passed verification. | Record the result and retain the checkpoint and predecessor files. |
| CHECKPOINT_INVALID | The document/hash is invalid, required predecessor is missing, or the supplied predecessor link/sequence is invalid. | Re-check that the original files are present and paired in the correct sequence. Do not edit a checkpoint to make it pass. |
| INSTALLATION_ID_MISSING | The local database has no valid persisted installation identity. | Stop and investigate the database/installation state. Do not create a replacement identity merely to bypass the mismatch. |
| INSTALLATION_ID_MISMATCH | The checkpoint belongs to a different AgentGuard installation identity. | Confirm that the API is connected to the intended database. A copied database retains its installation identity; a different installation should not be treated as the same one. |
| CHECKPOINT_MISMATCH | A checkpointed operation or event prefix is missing/changed, or the local event chain is invalid. | Treat this as an integrity incident until explained. Preserve the database and all checkpoint files for investigation; do not overwrite the evidence. |

For CHECKPOINT_MISMATCH, the response may include a detail such as:

- CHECKPOINTED_OPERATION_MISSING
- CHECKPOINTED_EVENT_PREFIX_MISSING
- CHECKPOINTED_EVENT_PREFIX_MISMATCH
- LOCAL_EVENT_CHAIN_INVALID
- PREVIOUSLY_CHECKPOINTED_OPERATION_MISSING
- PREVIOUSLY_CHECKPOINTED_EVENT_PREFIX_MISSING
- PREVIOUSLY_CHECKPOINTED_EVENT_PREFIX_MISMATCH

Authentication failures return HTTP 401. Export may return HTTP 422 for invalid predecessor input or HTTP 503 when local checkpoint storage/audit state is unavailable or inconsistent. For verification, inspect both the HTTP status and the JSON valid/reason_code result.

## 8. Changes that are expected to pass

Verification allows normal append-only growth after a checkpoint:

- New events appended after the checkpointed event prefix are allowed.
- New Gateway operations created after the checkpoint are allowed.
- The hash at the checkpointed event-count position must still match.

By contrast, deleting a previously checkpointed operation, removing events from its checkpointed prefix, changing that prefix, or breaking the local event chain must fail verification.

A later checkpoint captures a newer point in time. It does not retroactively change what an earlier checkpoint covered.

## 9. If verification fails

1. Stop routine checkpoint rotation until the result is understood.
2. Preserve the SQLite database and every external checkpoint file exactly as found.
3. Confirm that the API is connected to the expected database and installation.
4. Confirm that the checkpoint and immediate predecessor are the original files and are in the correct order.
5. Record the HTTP status, reason_code, optional detail, checkpoint sequence, and checkpoint hash. Do not include bearer tokens.
6. Investigate the cause before taking corrective action. If the local database is corrupted or history is missing, use a separate verified database backup and an established database recovery procedure.

**A checkpoint cannot restore the database.** It contains hashes and metadata, not the deleted event rows or full database contents. Restore requires a separate backup strategy; checkpoint verification can help determine whether a restored database matches a previously retained checkpoint.

## Security boundary

The checkpoint protects only while the external copy remains independently trustworthy. If an attacker can rewrite the local SQLite database and replace every external checkpoint copy, the attacker can replace the evidence too. SHA-256 hashes provide integrity linkage; they do not authenticate the publisher.

AgentGuard does not hold wallet keys, sign or broadcast transactions, or move real funds. Checkpoint functionality does not change that simulation-only boundary.
