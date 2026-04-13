# Architecture Notes

## Components

- `run.py`
  Starts the Flask app and registers the API and lab blueprints.

- `core/security.py`
  Generates and verifies an OpenID-style callback assertion, including
  `claimed_id`, `identity`, `return_to`, `realm`, `assoc_handle`,
  `response_nonce`, `signed`, and `sig`. It also exposes the provider-side
  verification logic and replay protection.

- `core/database.py`
  Stores seeded local accounts, session state, incident logs, and the set of
  already-accepted callback nonces.

- `lab/routes.py`
  Provides the consumer login pages, the local provider simulation, the
  provider-side `check-authentication` endpoint, and the vulnerable/secure
  callback paths used in the manual lab.

- `api/routes.py`
  Exposes supporting JSON endpoints for signing, provider verification, account
  state, and incident logs.

## Consumer and Provider Roles

SentinelAuth models two roles inside the same local app:

- the **consumer** or relying party
- the **provider** that issues and verifies the callback assertion

This keeps the project local and easy to demo while still separating the two
trust boundaries conceptually.

## Vulnerable Flow

1. The user opens a consumer page such as `/lab/login/vulnerable`.
2. The consumer redirects the user into a local provider screen.
3. The provider validates local credentials and generates an assertion.
4. The browser is redirected back to `/lab/callback/vulnerable` with callback parameters.
5. If the request is intercepted and `openid.claimed_id` / `openid.identity` are modified, the vulnerable callback still trusts the modified identity.

## Secure Flow

1. The user follows the same provider-style login path.
2. The provider generates the same assertion structure.
3. The browser is redirected back to `/lab/callback/secure`.
4. The secure consumer POSTs the received assertion back to `/lab/provider/check-authentication`.
5. The provider-side verification logic recomputes and validates the signed fields.
6. The consumer accepts the callback only if the provider returns `is_valid:true`.
7. The consumer then performs replay protection by rejecting any nonce that has already been accepted.
8. If the identity was modified after signing, or if the nonce is replayed, validation fails and the request is rejected.

## Security Properties Demonstrated

- identity tampering
- integrity validation
- provider-to-consumer trust boundaries
- network-level provider assertion verification
- replay-window enforcement
- nonce replay protection
- manual exploit reproduction
- visible difference between insecure trust and cryptographic verification
