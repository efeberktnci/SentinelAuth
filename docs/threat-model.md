# Threat Model

This document defines the threat model for SentinelAuth and clarifies what the
lab is intended to demonstrate.

## Security Objective

The primary objective is to protect account ownership during an external
identity-provider callback flow.

The consumer must ensure that the identity claim received in the callback still
belongs to the same account that the provider originally authenticated and
signed.

## Assets

The important assets in this lab are:

- account ownership
- authenticated session state
- callback integrity
- signed assertion fields
- replay resistance for previously accepted assertions

## Attacker Knowledge

The attacker is assumed to know:

- their own valid account credentials
- the target account identifier
- the callback route structure
- the shape of the callback parameters

The attacker does not need:

- access to the target account password
- access to the provider secret key
- code execution on the server

## Attacker Capabilities

The attacker can:

- authenticate as their own low-privilege account
- intercept their own browser traffic with a proxy
- modify callback parameters before they reach the consumer
- replay a previously captured callback request

The attacker specifically attempts to tamper with:

- `openid.claimed_id`
- `openid.identity`

## What the Attacker Cannot Forge

The attacker cannot legitimately forge:

- the provider secret used to compute the HMAC
- a valid signature for a modified identity
- a provider verification response that honestly returns `is_valid:true` for a tampered assertion

This assumption is what makes integrity validation meaningful in the secure flow.

## Trust Boundaries

The key trust boundaries in SentinelAuth are:

1. Browser to Consumer
   The callback request travels through the browser and can be intercepted.

2. Consumer to Provider
   The secure consumer does not trust the browser-delivered assertion on its own.
   It sends the packet back to the provider-side verification endpoint.

3. Provider Signing Boundary
   The provider is trusted to bind the original authenticated identity to the
   signed assertion fields.

## Why the Vulnerable Flow Breaks

The vulnerable callback fails because it trusts the claimed identity directly
after the browser returns the callback.

That means:

- the browser becomes an unintended source of truth for account identity
- a tampered `claimed_id` can replace the original authenticated identity
- the consumer never asks the provider whether the modified assertion is still valid

In other words, the consumer trusts a field that crossed an attacker-controlled
boundary without re-validating it.

## Why the Secure Flow Holds

The secure flow relies on these assumptions:

- the provider secret remains secret
- the provider-side verification logic is correct
- the consumer sends the received assertion back to the provider for validation
- the consumer rejects reused nonces

Under those assumptions, the secure flow blocks:

- identity tampering
- malformed assertion fields
- mismatched identity claims
- replay of already accepted callback packets

## Residual Limitations

This lab is a local simulation, not a live third-party provider integration.

That means it demonstrates the vulnerability class and mitigation strategy very
well, but it does not claim to be the exact internal implementation of any real
service.

## Summary

SentinelAuth models a callback-integrity problem where the attacker controls the
transport path between provider and consumer but cannot forge provider signing
material.

The vulnerable flow breaks because it trusts browser-delivered identity claims.
The secure flow holds because it re-validates the assertion across the provider
trust boundary and enforces replay protection.
