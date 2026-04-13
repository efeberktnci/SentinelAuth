# Manual Walkthrough

This document explains how to reproduce the vulnerable and secure callback behaviors in SentinelAuth by manually intercepting and modifying requests with Burp Suite.

## Goal

The goal is to show the difference between:

- a vulnerable callback that trusts the claimed identity directly
- a secure callback that performs a provider-style `check_authentication` round-trip before accepting that identity

## Local Accounts

Use these seeded local accounts:

- `attacker` / `attacker123`
- `operator` / `operator123`

Mapped identifiers:

- `attacker` -> `76561198987654321`
- `operator` -> `76561198123456789`

## Start the App

```powershell
cd C:\Users\Efeberk\Desktop\SentinelAuth
python run.py
```

Open one of the two consumer entry points:

- vulnerable login: `http://127.0.0.1:5000/lab/login/vulnerable`
- secure login: `http://127.0.0.1:5000/lab/login/secure`

## Prepare Burp Suite

1. Open Burp Suite Community Edition.
2. Use a temporary in-memory project.
3. Start Burp with default settings.
4. Open `Proxy`.
5. Turn `Intercept` on when you want to pause requests.

## Step 1: Start the Vulnerable Consumer Flow

Open the vulnerable login page, then click `Continue to Provider`.

![Consumer entry page](./assets/login-page.png)

The browser is redirected to the local provider simulation, where you should authenticate as:

- `username`: `attacker`
- `password`: `attacker123`

![Provider page](./assets/provider-page.png)

At this point Burp intercepts the first provider request:

- `POST /lab/provider/authorize/vulnerable`

Do not modify this request. Just forward it.

## Step 2: Intercept the Callback Request

After forwarding the provider authorization, Burp should intercept the callback:

- `GET /lab/callback/vulnerable?...`

![Callback intercepted in Burp](./assets/tampered-callback.png)

This is the important request. In the raw request, find these two parameters:

- `openid.claimed_id`
- `openid.identity`

Both will initially contain the low-privilege account identifier:

- `76561198987654321`

Replace that value in both parameters with the target account identifier:

- `76561198123456789`

Do not modify:

- `openid.sig`
- `openid.response_nonce`
- `openid.signed`

Then forward the request.

## Step 3: Observe the Result

If the vulnerable path is working as intended, the consumer accepts the tampered identity and creates a session for the target account.

The browser should then load the target account dashboard.

![Target account dashboard](./assets/account-dashboard.png)

## Repeat Against the Secure Flow

Now repeat the same process using:

- `http://127.0.0.1:5000/lab/login/secure`

Use the same provider credentials:

- `attacker` / `attacker123`

Again intercept:

- `GET /lab/callback/secure?...`

Again replace:

- `76561198987654321`

with:

- `76561198123456789`

in both:

- `openid.claimed_id`
- `openid.identity`

Leave `openid.sig` untouched.

This time the request should fail because the secure consumer now does two things:

1. it POSTs the received assertion back to `/lab/provider/check-authentication`
2. it refuses to reuse an `openid.response_nonce` that has already been accepted

Expected result:

- the request is rejected
- the browser shows the blocked page with the validation reason

![Secure flow denied](./assets/secure-denied.png)

## Optional Replay Test

After a successful secure login, resend the exact same callback request one more time.

Expected result:

- the request is rejected
- the reason says the nonce has already been accepted

This models a relying party that not only validates the assertion with the provider but also remembers which callback nonces have already been consumed.

## Why the Vulnerable Flow Fails

The vulnerable callback extracts the identifier from `openid.claimed_id` and accepts it if that account exists locally.

It does not:

- send the assertion back to the provider for verification
- verify that `openid.identity` still matches `openid.claimed_id`
- enforce nonce replay protection

## Why the Secure Flow Works

The secure callback behaves more like a real relying party:

- it validates the OpenID-style packet shape
- it sends the assertion back to the provider-style `check_authentication` endpoint
- it only proceeds if the provider says `is_valid:true`
- it stores accepted nonces and blocks replay attempts

If the claimed identifier was changed after signing, provider verification fails.

If the packet is replayed without modification, nonce tracking fails it on the consumer side.

## Suggested Demo Order

If you present this project live:

1. Show the home page and briefly explain the two validation paths.
2. Open the vulnerable consumer login page.
3. Continue to the provider and authenticate as `attacker`.
4. Intercept the vulnerable callback.
5. Change the identifier to the target account.
6. Show the successful account takeover.
7. Repeat the same process against the secure page.
8. Show that the second attempt is rejected.
9. Optionally resend the same secure callback again and show replay protection.
