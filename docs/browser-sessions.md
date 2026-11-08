# Browser session lifecycle

Browser login requests to `/v1/auth/exchange`, `/v1/auth/email/verify-code`, and
`/v1/auth/near` send `X-Session-Client: user` or `admin`, plus the browser Origin.
The existing PKCE callback flow is unchanged. Admin issuance also requires the
current admin domain and email allowlists; choosing the header grants no privilege.
There is no endpoint that upgrades an existing bearer token into an admin session.

Configure comma-separated **exact origins**, without paths or trailing slashes:

- `BROWSER_SESSION_USER_ORIGINS`: production/staging user frontend origins.
- `BROWSER_SESSION_ADMIN_ORIGINS`: trusted admin frontend origins only.
- CORS must also permit these exact origins and `X-Session-Client`.

Missing origin configuration denies browser login/refresh/logout. Wildcards are
not accepted by these endpoints even if the general CORS policy permits them.
Use disjoint user/admin origin lists. Reject untrusted preview deployments.
Cookies are Secure, HttpOnly, host-only `__Host-nearai_user_refresh` and
`__Host-nearai_admin_refresh`, Path=/, SameSite=Lax. The frontend and API must be
same-site HTTPS (same registrable domain), or use a same-site API proxy. A frontend
on an unrelated custom/preview domain cannot rely on these cookies. Local HTTP
loopback origins can be allowlisted, but browser Secure-cookie behavior must be
verified; local HTTPS is the portable setup. Do not loosen cookies for production.

## Lifetime and revocation

| Credential/session | Lifetime |
| --- | --- |
| Browser access token | At most 15 minutes, bounded by family deadlines |
| User session family | 30-day absolute, 7-day idle |
| Admin session family | 8-hour absolute, 30-minute idle |

Access tokens remain opaque `sess_` credentials. Database lookups check the access,
absolute, and idle deadlines on every authenticated request. All secrets are stored
as hashes; refresh secrets contain 256 random bits and never appear in JSON.
Multiple access tokens per family allow independent tabs to remain authenticated.

`POST /v1/auth/session/refresh` accepts `{ "active": false }` by default and returns
`{ token, session_id, expires_at }` with a rotated refresh cookie. Only recent user
interaction should send `active: true`; background polling must use false. The
clients refresh on demand, at most once per minute for activity, and otherwise
near access expiry. Refresh never extends absolute expiry. The activity hint is a
client behavior contract, not proof of human presence; absolute expiry remains the
server-enforced upper bound even against a malicious client.

Refresh locks the parent session row. Reusing any consumed refresh token deletes
the family, invalidating all its access and refresh credentials. Consumed hashes
are retained until family deletion for replay detection. A lost refresh response
can therefore require a fresh sign-in: do not automatically retry or add a replay
grace window. Web Locks serialize cookie-changing requests across tabs on the same
origin. Clients without Web Locks fail closed. No credentials cross BroadcastChannel.

`POST /v1/auth/session/logout` uses the refresh cookie and the same strict origin
checks, so access-token expiry does not prevent logout. It accepts consumed refresh
tokens to resolve refresh/logout races. Bearer-authenticated `/v1/auth/logout`
also deletes the family through the existing session root. Revocation affects new
requests; it does not terminate a stream or operation already authorized in flight.

Expired access tokens are removed on family refresh. Every API replica also runs
browser-family cleanup at startup and every five minutes, deleting expired roots
in batches of at most 500 (at most ten batches per pass). Row locks with SKIP LOCKED
avoid contention with refresh/logout and other replicas. Cascading deletion removes
access tokens and replay tombstones only when the family has expired. Cleanup errors
are logged and retried on the next tick. V44 indexes idle-expiry selection.

Browser setup failures attempt to revoke the original session, including admin
lookup failures and failures after family creation. If the database is unavailable,
revocation is best effort and the failure is logged; no credential is returned.

## Coordinated rollout and cutoff

1. Apply V43/V44 and deploy the backend with the exact origin lists. Keep
   `SESSION_ENFORCE_SHORT_TOKENS` unset initially for old clients.
2. Deploy both UI PRs. They purge old persisted credentials, require a fresh login,
   store access tokens only in memory, and restore through the refresh cookie.
   Newly issued user browser sessions cannot access admin routes even during rollout.
3. Verify production/staging cookies, login methods, multi-tab behavior, reload,
   idle expiry, logout, and SSE initiation. Test the actual mobile clients before
   proceeding: native clients do not receive a refresh-token JSON fallback here.
4. Set `SESSION_ENFORCE_SHORT_TOKENS=true` consistently on every API replica.
   This caps **existing and new** legacy tokens at `created_at + 15 minutes` and
   requires an admin browser session on admin routes. Older sessions become invalid;
   this is the explicit reauthentication cutoff. Without this step, legacy long-lived
   credentials remain accepted for compatibility and the rollout is not complete.
5. Do not disable the enforcement flag as a rollback: doing so can revive old
   credentials. Keep enforcement enabled when rolling back UI changes, or revoke
   legacy sessions permanently first. Do not roll back to an API without these checks.

## External dependencies

Mobile/API consumers that currently use 30-day session bearers need a tested
short-token/reauthentication path before cutoff; unattended integrations should use
appropriate scoped API keys. This PR does not change agent API key lifetimes.

Login also establishes an independent compose-api/gateway cookie. Its expiry and
server-side revocation are owned outside these three repositories. Chat-api family
revocation does not revoke that credential. Audit and coordinate gateway logout
separately; do not claim global gateway sign-out from these endpoints. No production
configuration or data is changed by this PR.
