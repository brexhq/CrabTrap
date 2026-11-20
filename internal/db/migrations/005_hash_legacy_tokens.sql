-- Tokens used to be stored as plaintext in user_channels.payload. Lookups now
-- hash the presented token before comparing (see admin.TokenHash), so legacy
-- plaintext rows would never match and every existing session would return 401.
-- Rewrite them to sha256 hex.
--
-- Every string value is hashed: the bootstrap CLI stored
-- hex.EncodeToString(32 random bytes), which is itself 64 lowercase hex, so the
-- value shape cannot tell a legacy token from an already-hashed one. Gating on
-- that shape left exactly those admins plaintext and permanently locked out.
-- One shot only — internal/db/migrate.go records applied filenames in
-- schema_migrations, so this file must not be re-run by hand (it would hash the
-- hashes). Non-string values are skipped rather than coerced to text.
UPDATE user_channels
SET payload = jsonb_set(payload, '{web_token}',
        to_jsonb(encode(sha256(convert_to(payload->>'web_token', 'UTF8')), 'hex'))),
    updated_at = NOW()
WHERE payload ? 'web_token'
  AND jsonb_typeof(payload->'web_token') = 'string';

UPDATE user_channels
SET payload = jsonb_set(payload, '{gateway_auth_token}',
        to_jsonb(encode(sha256(convert_to(payload->>'gateway_auth_token', 'UTF8')), 'hex'))),
    updated_at = NOW()
WHERE payload ? 'gateway_auth_token'
  AND jsonb_typeof(payload->'gateway_auth_token') = 'string';
