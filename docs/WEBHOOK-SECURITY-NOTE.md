# Note: webhook secret storage

The current `WebhookSource.hmac_secret_hash` column stores the **raw HMAC
secret**, not a bcrypt hash. HMAC verification requires the plaintext secret
to compute the expected signature, so we cannot store it hashed. The column
name is a misnomer — kept as-is for v1 to avoid an early migration churn.

## What this means operationally

- The DB now contains a secret that, if leaked, allows an attacker to forge
  webhook payloads (one source at a time).
- Mitigations in place:
  - The secret is shown to the admin **once** at creation and never returned by any API after.
  - The column is `Text`, not indexed — no leak via query logs.
  - Webhook ingest also enforces a 5-minute timestamp skew window, blocking replay outside that window.
  - Optional `ip_allowlist` on the source row.

## Future migration (when needed)

Move webhook secret storage to one of:

1. **Envelope encryption** — encrypt the secret with a KMS/server-key column,
   decrypt only at HMAC verification time. Adds a `secret_ciphertext`,
   `secret_nonce`, `kms_key_id` columns.
2. **External secret store** — Hashicorp Vault / AWS Secrets Manager,
   reference by `secret_path` only.
3. **Stable secret IDs** — each webhook source rotates secrets and the
   plaintext lives only in a KMS; the DB stores a reference.

This is captured here so it does not get lost in code comments inside
`routes/webhooks.py`.
