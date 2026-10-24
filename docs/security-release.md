# Provider PKCE and security headers rollout

This release adds provider PKCE to Google/GitHub sign-in and security response
headers to the API, bundled frontend, and documentation routes. It does not
remove the frontend wallet SDK's `script-src 'unsafe-inline'` requirement.

## Before production

- Configure the same database encryption key and key ID on every replica.
  Provider PKCE verifiers are always encrypted, even when
  `DB_ENCRYPTION_WRITE_ENABLED=false`; missing encryption configuration rejects
  new verifier writes. Other confidential fields retain their existing rollout
  gates. Invalidate pending states containing plaintext verifiers at cutover
  and require those logins to restart; previously stored plaintext verifiers
  are not retroactively protected by this change.
- Exercise Google and GitHub sign-in on staging using the registered callback
  URL and real provider configuration. Local tests validate provider parameters
  and the Google token exchange with a mock provider; they do not validate the
  production app registrations or proxy routing.
- Check that the final proxy preserves HSTS on the frontend, API, errors,
  `/docs`, `/docs/`, a Swagger asset, and `/api-docs/openapi.json`. HSTS is
  `max-age=31536000; includeSubDomains`; HTTPS must remain available for the host
  and its subdomains for that period. Removing the header does not immediately
  clear policies already cached by browsers.
- Smoke-test wallet selection and signing after the frontend CSP attribute
  restriction. The existing inline script elements remain allowed; inline
  event-handler attributes are rejected.
- Apply V41 once using the normal migration runner before new instances become
  ready. Startup also runs migrations. The migration adds a UUID column with a
  volatile random default and a unique constraint, so allow for a table rewrite
  and an exclusive lock on `oauth_states`. Check table size and lock contention
  on the actual database; local tests do not establish production lock duration.

## Cutover

Do not randomly distribute OAuth initiation and callback requests across old
and new replicas during the switch. Drain the old version and cut new login
traffic over together, or use version-affine routing for both legs. Existing
application sessions remain usable.

Pre-release pending states have no provider verifier. A new callback rejects
them. Conversely, an old callback cannot exchange a provider code issued with
the new PKCE challenge. Those logins must restart; retrying the same callback
does not work because state is consumed once before token exchange. Never
accept a missing verifier as a compatibility fallback.

## Rollback

V41 is additive and keeps the old `state` primary key, so old query shapes still
work. That does **not** mean an unchanged old image can start after migration.
The existing refinery runner rejects applied migrations absent from its local
SQL files. An image containing only V1–V40 fails startup after V41 is applied.

Prepare and test a rollback image that includes the exact V41 SQL file as well
as the original migration set, or supply the complete preserved V1–V41 SQL
directory via `DATABASE_MIGRATIONS_PATH`. Preserve migration names and bytes;
do not remove V41 from migration history or drop its columns during rollback.
Use an absolute path and ensure the mounted directory exists: the runner falls
back to bundled paths when an override path is absent.

Drain/cut over login traffic as above when reverting code. New-version pending
PKCE logins cannot finish on the old code and must restart. Code rollback also
removes provider PKCE protection, so prefer a forward fix when possible. Reverting
HSTS at the server cannot undo the policy cached in clients immediately.

The production provider smoke tests, proxy-header check, database lock check,
and rollback-image startup check are release prerequisites. Passing local tests
alone is not evidence of a zero-risk production rollout.

## Frontend PKCE and token-mode removal (V42)

Google/GitHub login requires frontend S256 PKCE and state in addition to provider
PKCE. The provider callback returns only a one-time code; application tokens and
gateway cookies are delivered only by a successful frontend code exchange.

V42 removes the persisted response-mode column and makes frontend challenge/state
mandatory. It deletes pending token-mode or incomplete states; those sign-ins must
restart. Existing application sessions are unaffected. Historical migration files
remain unchanged for refinery checksum validation.

Upgrade supported Web/mobile/Tauri clients before backend cutover. Drain old API
replicas before applying V42 and route new login traffic only to the new version;
old repository queries reference the removed column and cannot run against V42.
Do not roll an unchanged old backend back onto this schema. Prefer a forward fix;
a rollback requires an explicitly reviewed compatible schema/code plan.

Before promotion, exercise Google/GitHub login, actual gateway cookie storage and
gateway access on Web, mobile browsers and Tauri. Confirm that bearer query/hash
URLs, desktop bearer GET and old channel handoffs cannot establish a session.
NEAR signed-message login and state-bound loopback POST remain supported.
