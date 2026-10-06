# HASHI Specification

**Human Agent Secure Handshake Identity**

- **Version:** 0.1 (draft)
- **Status:** Experimental
- **Editor:** Rob Cleghorn
- **Licence:** Apache-2.0

> *Got a hashi?*

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Hashis](#3-hashis)
4. [Resolution and the Hashi Document](#4-resolution-and-the-hashi-document)
5. [Keys and Delegation](#5-keys-and-delegation)
6. [Trust Levels](#6-trust-levels)
7. [Offers](#7-offers)
8. [Protocol Operations](#8-protocol-operations)
9. [Handover and Protocol Bindings](#9-handover-and-protocol-bindings)
10. [Common Workflows](#10-common-workflows)
11. [Network Security](#11-network-security)
12. [Security Considerations](#12-security-considerations)
13. [Privacy and Safety](#13-privacy-and-safety)
14. [IANA Considerations](#14-iana-considerations)
- [Appendix A: Relationship to Other Protocols](#appendix-a-relationship-to-other-protocols)
- [Appendix B: Open Questions](#appendix-b-open-questions)
- [Appendix C: References](#appendix-c-references)

---

## 1. Introduction

HASHI is a human relationship and discovery layer for the agentic internet.

People increasingly hand correspondence, scheduling and negotiation to AI agents. Agent-to-agent protocols such as A2A define how agents talk to each other, and leave credentials to be obtained separately. Nothing defines how a person gives their agents an address others can use, how that person decides who may reach them, or how trust formed between two people (say, after meeting on the street) carries across to their agents.

HASHI fills that gap the way a phone number and an address book do for calls:

1. A **hashi** is an address you hand out: `john#my.domain`.
2. An **offer**, usually a QR code or link, invites someone in at a trust level.
3. **Redeeming** the offer records a **grant**.
4. Later, the other person's agent **knocks**. HASHI checks who it is and what they're allowed, picks a protocol both sides speak, and **hands over**.
5. The agents talk directly, over A2A or similar. HASHI steps out of the way.

### 1.1 Key Goals

- **People first.** A relationship is between people. Agents, devices, keys, providers and protocols can all change underneath it without breaking it. This is the central invariant of the protocol.
- **Signalling only.** HASHI never carries conversation content. It sets things up and gets out of the way.
- **Open and federated.** Anyone can run a HASHI server, much as anyone can run a mail server.
- **Simple to start.** No DNS changes per user, plain HTTPS on port 443, standard JOSE signatures.
- **Like email, you need an address.** HASHI only connects people who have a hashi. Someone without one can't be reached or use an offer until they get one, so every shared link is also an invitation to get one.

### 1.2 Scope

| In scope | Out of scope |
|----------|--------------|
| Hashi syntax and resolution | What agents do after the handover |
| Identity keys and delegation | The meaning of trust levels 1 to 8 |
| Trust levels, offers and grants | How a HASHI app presents offers and confirmations to its user |
| Knocks, protocol selection and handover | Any message channel or conversation content |

Responsibility for agent behaviour rests with whoever operates the agent. This specification is a guide: implementations decide what each trust level unlocks.

### 1.3 Requirements Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in bold capitals.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Owner** | The person (or organisation) a hashi belongs to. |
| **Hashi** | A human-readable address of the form `local#domain`. |
| **Display name** | An optional name for presentation only. Never an identifier. |
| **HID** (hashi ID) | A stable identifier derived from the owner's first identity key. Survives key rotation, renaming and changing provider. |
| **Identity key** | The owner's root signing key. Signs the binding, delegations and rotations, and nothing else. |
| **Device key** | A key on one of the owner's devices, delegated by the identity key. Signs offers. |
| **Server key** | A key held by the HASHI server, delegated through the binding. Signs grants, freshness statements and handover credentials. |
| **Agent key** | A key held by an agent, delegated by the identity key. |
| **HASHI server** | The always-on service that publishes the hashi document, redeems offers and answers knocks. |
| **Requester** | The party making contact: an agent (an app or AI acting for someone) whose owner has a hashi. |
| **Trust level** | An integer from 0 to 9 that one party grants another. Trust is directional. |
| **Offer** | A signed, usually one-time invitation stating the maximum trust level its redeemer may receive. |
| **Grant** | A trust level recorded by a HASHI server for a specific HID. |
| **Knock** | A signed request to reach an owner's agent. |
| **Handover** | The answer to an accepted knock: a protocol, an agent endpoint and a credential. |
| **Epoch** | A counter the owner increments on every signed change to their hashi document. |

---

## 3. Hashis

### 3.1 Syntax

A hashi is a local part and a domain separated by `#`.

```abnf
hashi    = local "#" domain
local    = 1*64( %x61-7A / DIGIT / "." / "-" / "_" )   ; lowercase after folding
domain   = <DNS name, A-label form when transmitted>
```

- The local part **MUST** be ASCII. Clients **MUST** fold uppercase to lowercase before comparing. The canonical form is lowercase.
- Internationalised domains **MUST** be transmitted as A-labels. Clients **SHOULD** display the U-label only when it is not confusable with another domain.
- Spoken aloud, a hashi is "local hash domain": *"john hash my dot domain"*.

**Reserved local parts.** These **MUST NOT** be issued to individuals: `admin`, `abuse`, `postmaster`, `security`, `hostmaster`, `webmaster`, `root`, `hashi`, `www`, `support`.

### 3.2 URI Form

`#` marks a fragment in URIs, so the `hashi` URI scheme reorders the hashi instead of encoding it:

| Form | Example |
|------|---------|
| Hashi (for people) | `john#my.domain` |
| URI (for software) | `hashi://my.domain/john` |
| Link (for QR codes and sharing) | `https://my.domain/.well-known/hashi/john` |

Clients **MUST** convert between these forms exactly as shown, and **MUST** treat the link form as equivalent to the URI form. Either **MAY** carry an offer in its fragment ([Section 7.2](#72-carrying-offers)).

### 3.3 Bare Hashis

A hashi with no offer carries no trust. Contact made with only a bare hashi is at level 0. Whether to accept level-0 knocks at all is owner policy, and implementations **MAY** ignore them.

> The hashi identifies and locates. Offers and grants authorise.

### 3.4 Display Names

An owner **MAY** publish a display name in the hashi document and **MAY** include one in offers.

- A display name **MUST NOT** be used for authentication, trust decisions, HID derivation, uniqueness or equality. Two people can both be called John Smith.
- Display names **MUST** be normalised to Unicode NFC, **MUST NOT** contain control, format or bidirectional-override characters (Unicode categories Cc and Cf), and **MUST NOT** exceed 128 characters. Clients **MUST** apply the same rules before display, and **MUST** reject or strip non-conforming values.
- Until the user has saved the other party as a contact, or granted them a level above 0, clients **MUST** show the hashi alongside any display name, never the name alone. Redeeming *their* offer doesn't count, because they control that step.
- Once a contact is saved, clients **SHOULD** prefer the user's own name for it.
- Owners **MAY** leave the display name out of the public document and supply it only in offers.

```text
John Doe          ← who a person sees
john#my.domain    ← the address
hid:Q3pT0gq...    ← the cryptographic identity
```

---

## 4. Resolution and the Hashi Document

### 4.1 Resolving a Hashi

To resolve `local#domain`, a client fetches:

```http
GET /.well-known/hashi/{local} HTTP/1.1
Host: {domain}
Accept: application/hashi+json
```

- HTTPS on the default port only. Clients **MUST NOT** assume any other port.
- Clients **MUST NOT** follow redirects. Hosting elsewhere is expressed by the `endpoint` field, not by redirection.
- Responses larger than 64 KiB **MUST** be rejected.

### 4.2 The Hashi Document

```json
{
  "version": "0.1",
  "hashi": "john#my.domain",
  "display_name": "John Doe",
  "hid": "hid:Q3pT0gq1mRk2b0nN7y3A5xYv9L6cF8hJ2sW4eD1uK0o",
  "epoch": 3,
  "identity_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "binding": "<JWS signed by identity key>",
  "fresh": "<JWS signed by server key>",
  "endpoint": "https://hashi.my.domain/v1",
  "level0": { "accept": true },
  "protocols": ["a2a/1.0"],
  "rotations": [],
  "revoked": ["dlg_1b9..."]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Protocol version. |
| `hashi` | string | Yes | Canonical hashi. |
| `display_name` | string | No | Presentation only ([Section 3.4](#34-display-names)). |
| `hid` | string | Yes | `hid:` plus the base64url JWK thumbprint (RFC 7638) of the owner's genesis identity key. |
| `epoch` | integer | Yes | Incremented on every signed change, including every revocation and rotation. |
| `identity_key` | JWK | Yes | The owner's current identity public key. |
| `binding` | JWS | Yes | Signed by the identity key ([Section 4.3](#43-the-binding)). |
| `fresh` | JWS | Yes | Freshness statement signed by the server key ([Section 4.5](#45-freshness)). |
| `endpoint` | URL | Yes | HTTPS base URL of the HASHI server API. May be on a different host from `{domain}`. |
| `level0` | object | No | `{ "accept": boolean }`. Default `false`. |
| `protocols` | string[] | No | Handover protocols the owner supports. Owners **MAY** omit this. |
| `rotations` | JWS[] | Yes | Rotation chain, oldest first. Empty if never rotated. |
| `revoked` | string[] | Yes | `jti` values of revoked, unexpired delegations. |

### 4.3 The Binding

The binding is how the owner, rather than whoever hosts the domain, vouches for everything in the document.

Its payload contains **every field of the document except `binding`, `fresh` and `rotations`**, plus:

| Field | Description |
|-------|-------------|
| `srv` | The server key (JWK). |
| `handover_hosts` | Hostnames the server may hand requesters over to ([Section 11](#11-network-security)). |
| `iat` | Issued-at time. |

Verifiers **MUST** check that every field of the document matches the binding.

### 4.4 Verification and Pinning

To verify a hashi document, a verifier **MUST**:

1. Verify the rotation chain from the genesis key (whose thumbprint **MUST** equal the HID) to `identity_key` ([Section 5.4](#54-key-rotation)).
2. Verify `binding` with `identity_key` and check it matches the document.
3. Verify `fresh` ([Section 4.5](#45-freshness)).

On first success, the verifier pins the HID, the identity key and the epoch. These rules apply to **every** verifier, clients and HASHI servers alike:

- A document with a **lower epoch** than the pinned one **MUST** be rejected. This stops a compromised host replaying an old document.
- A **new identity key with a valid rotation chain** **MUST** be accepted silently, and the pins updated.
- A **different HID**, or a key change **without** a valid chain, **MUST** be treated as a new identity. Clients **MUST** warn the user, as Signal does for a changed safety number, and **MUST NOT** carry any trust above level 0 across to it automatically.

### 4.5 Freshness

Pinning protects only a verifier that has already seen the latest epoch. Freshness limits how long a stale document can fool one that hasn't.

- The HASHI server **MUST** serve `fresh`: a JWS signed by the server key with payload `{ "hid", "epoch", "iat" }`, re-signed at least every hour.
- Verifiers **MUST** reject a document whose `fresh` is older than 24 hours or whose epoch doesn't match.
- Verifiers **MUST NOT** rely on a cached hashi document older than one hour when deciding a redeem or knock.

---

## 5. Keys and Delegation

### 5.1 Algorithms

Signatures use JWS. Implementations **MUST** be able to verify both:

| Algorithm | Curve | Why |
|-----------|-------|-----|
| `EdDSA` | Ed25519 | Compact and widely used. |
| `ES256` | P-256 | What mainstream hardware key stores (Apple Secure Enclave, Android StrongBox) provide. |

Implementations **MAY** sign with either.

### 5.2 Key Roles

```text
                  identity key (root, defines the HID)
        ________________|________________________
       |               |              |          |
   binding          device keys    agent keys  rotations
   (server key)        |              |
       |            sign offers   sign redeems, knocks,
  signs grants,                   polls; prove possession
  fresh, credentials              in agent sessions
```

- The identity key signs **only** the binding, delegations and rotations. It **SHOULD** be kept off everyday devices (for example in platform end-to-end-encrypted key sync, a recovery phrase or a hardware token) and **SHOULD** be reachable from more than one place, because revoking a lost device needs it.
- Device, agent and server keys **SHOULD** be held in hardware-backed, non-exportable storage where available. Device keys **SHOULD** require a biometric or PIN to sign.
- The identity key **MUST NOT** be given to the HASHI server or to any agent.

Losing a phone means revoking that phone's device key, not rebuilding your identity.

### 5.3 Delegation Certificates

Device and agent keys are authorised by a delegation: a compact JWS signed by the identity key. It carries the delegated public key, so anyone can verify a signature without prior history.

```json
{
  "typ": "hashi-dlg+jwt",
  "iss": "hid:Q3pT0gq...",
  "role": "agent",
  "hashi": "john#my.domain",
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "max_lvl": 6,
  "epoch": 3,
  "iat": 1791270000,
  "exp": 1793862000,
  "jti": "dlg_7f3a..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | The owner's HID. |
| `role` | string | Yes | `device` or `agent`. |
| `hashi` | string | Yes | The owner's hashi. |
| `cnf.jwk` | JWK | Yes | The delegated public key. |
| `max_lvl` | integer | Yes | Agent: highest level it may act at. Device: highest offer level it may sign. |
| `epoch` | integer | Yes | The owner's epoch at issue. |
| `iat`, `exp` | integer | Yes | `exp` **MUST NOT** be more than 90 days after `iat`. Device delegations **SHOULD** be short-lived (for example 30 days). |
| `jti` | string | Yes | Unique ID, used for revocation. |

A verifier **MUST** reject a delegation that:

- is expired, or lasts more than 90 days;
- appears in `revoked`;
- is not signed by the current identity key; or
- has an `epoch` lower than that of the most recent rotation. (A rotation therefore kills every earlier delegation, including any minted with a stolen key.)

Verifiers **MUST** also check `role`: offers **MUST** be signed by a `device` delegation; redeems, knocks, polls and introspection **MUST** be signed by an `agent` delegation.

### 5.4 Key Rotation

A rotation statement is a compact JWS signed by the **outgoing** identity key:

```json
{
  "typ": "hashi-rotation+jwt",
  "hid": "hid:Q3pT0gq...",
  "epoch": 3,
  "old": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "new": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "iat": 1791270000
}
```

- Each statement includes the outgoing public key, so every link verifies on its own. The first `old` **MUST** have a thumbprint equal to the HID; each later `old` **MUST** equal the previous `new`.
- Each `epoch` **MUST** be greater than the previous one.
- After rotating, the owner **MUST** publish a new binding signed by the new key and **MUST** reissue delegations, because older ones stop verifying.

### 5.5 Lost or Stolen

| Situation | What happens |
|-----------|--------------|
| **Lost or stolen device** | The owner revokes its delegations (this needs the identity key, as it changes the binding). Short-lived offers from that device expire on their own, and the delegation's expiry is the backstop until it is revoked. The identity is unaffected. |
| **Identity key compromised, still in the owner's hands** | Rotate to a new key and revoke everything. |
| **Identity key lost, or an attacker may have rotated first** | Reset: a new identity key and therefore a new HID. Contacts see a new identity, trust drops to 0, and the owner shares fresh offers. A reset is always possible. |

---

## 6. Trust Levels

### 6.1 Scale

| Level | Meaning |
|-------|---------|
| **0** | Public. No proof needed. The default for bare hashis and strangers. |
| **1–8** | Ordered, owner-defined. Higher means more trusted. |
| **9** | Highest trust. |

Only 0 and 9 have protocol-defined meanings. Implementations decide what 1 to 8 unlock and **SHOULD** let owners configure it.

### 6.2 Rules

1. **Directional.** Each party sets only the level it grants the other. Redeeming an offer gives the redeemer a grant and gives the offer's issuer nothing. To trust someone back, issue your own offer.
2. **Belongs to the person.** A grant is recorded against the requester's HID, never an agent or device key, so it survives changes of agent, device or key.
3. **Offer as ceiling.** The server **MUST NOT** record a grant above the offered level, and **MAY** record a lower one.
4. **Lowering is unilateral.** An owner **MAY** lower or revoke a grant at any time.
5. **Raising needs a new offer.** A grant **MUST NOT** be raised except by redeeming a new offer at the higher level.
6. **Prospective only.** Changes apply from the moment they're made. Anything completed under a grant that was valid at the time stays done. Short credential lifetimes limit how long a lowered level lingers in an open session.
7. **Policy belongs to the owner's software.** Which levels may be offered remotely or in person, on multi-use offers, or with what expiry, is up to the owner's implementation. The protocol only carries the level and enforces it as a ceiling.

### 6.3 Effective Level

When a knock arrives, the effective level is the **lowest** of:

- the level the server currently records for the requester (0 if none);
- the level in the presented grant token, if any; and
- the requester's agent delegation `max_lvl`.

The server's record is authoritative, so lowering a grant takes effect at the very next knock.

### 6.4 Zero Is Zero

Dropping someone to 0 puts them back among the strangers. If the owner doesn't accept level-0 knocks, the server **MUST** answer `nah`, which makes it a complete block.

If the owner does accept level 0, implementations **MAY** refuse specific HIDs at level 0 as a matter of owner policy. A refusal **MUST** look exactly like any other `nah`, so nobody can tell they've been singled out.

---

## 7. Offers

### 7.1 The Offer Token

An offer is a compact JWS signed by a **device key**. Its protected header carries the device's delegation in the `dlg` parameter.

```json
{
  "typ": "hashi-offer+jwt",
  "iss": "hid:Q3pT0gq...",
  "hashi": "john#my.domain",
  "display_name": "John Doe",
  "lvl": 4,
  "nonce": "b9Xk2...",
  "one_time": true,
  "iat": 1791270000,
  "exp": 1791442800,
  "note": "coffee"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | Yes | The owner's HID. |
| `hashi` | string | Yes | The owner's hashi. |
| `display_name` | string | No | As in [Section 3.4](#34-display-names). |
| `lvl` | integer | Yes | Maximum level the redeemer may be granted. |
| `nonce` | string | Yes | **MUST** contain at least 128 bits of randomness. |
| `one_time` | boolean | Yes | One-time offers **MUST** be accepted at most once. |
| `iat`, `exp` | integer | Yes | One-time offers **SHOULD** expire within 48 hours. |
| `note` | string | No | Up to 140 characters of untrusted display text, normalised like display names. **MUST NOT** be passed to an agent or language model as instructions. |

Multi-use offers (say, one printed on a business card) are allowed; what level they carry is the owner's choice.

**Verifying an offer.** A verifier **MUST** resolve the offer's `hashi` and check that:

- the offer's `iss`, the `dlg` delegation's `iss` and the resolved document's `hid` are all equal;
- the delegation's `hashi` equals the offer's `hashi`;
- the delegation verifies against that document's identity key and has role `device`; and
- `lvl` does not exceed the delegation's `max_lvl`.

A HASHI server redeeming an offer **MUST** apply these checks against its own record of the hashi, so nobody can mint offers for a hashi they don't own. Redeemers **MUST** use the `endpoint` from the verified hashi document.

### 7.2 Carrying Offers

An offer is a capability: whoever redeems it first gets the grant. It therefore travels in the URI **fragment**, which is never sent to a server and so stays out of server logs, browser history, Referer headers and link-preview bots.

**QR codes and shared links SHOULD use the HTTPS form**, on the offerer's domain:

```text
https://my.domain/.well-known/hashi/john#o=<offer>
```

Any phone camera can open it, with no app needed. A link that only works if the right app is installed is a dead end for everyone else, and a custom scheme like `hashi://` can be claimed by any app on the phone, so whoever registers it first could grab the offer.

- **HASHI apps MUST recognise the HTTPS form** as well as `hashi://`, so an app's own scanner opens either. The two convert mechanically ([Section 3.2](#32-uri-form)).
- **The page at the HTTPS form** is the same URL as resolution ([Section 4.1](#41-resolving-a-hashi)), told apart by content negotiation: a request accepting `application/hashi+json` gets the hashi document, and a browser gets the owner's page. The page has one job, asking *"Got a hashi?"*:
  - **Yes:** an "Open in app" button passes the offer to a HASHI app on the device as a `hashi://` link.
  - **No:** it points to where to get one (app stores or providers), then asks the person to tap the link again.

  The page **MUST NOT** redeem offers, hold keys, or offer any chat or messaging. It **MAY** show the offer's display name and hashi. This is the same pattern as WhatsApp's `wa.me` and Telegram's `t.me` links.
- `hashi://` links remain valid wherever an app is known to be installed, for example between two HASHI apps.

### 7.3 Short Codes

Where a QR code or link won't do, the HASHI server **MAY** issue a short code that points to an offer it stores: 8 characters of Crockford base32, read aloud in two groups of four (`7KQ2-M9XD`).

- Short codes **MUST** be one-time and **MUST** expire within 48 hours.
- They are redeemed together with the hashi they were issued for (`to`).
- The server **MUST** limit failed attempts per hashi.

---

## 8. Protocol Operations

All operations are HTTPS requests to the `endpoint` from the owner's hashi document.

| Operation | Method and path | Purpose |
|-----------|-----------------|---------|
| Resolve | `GET https://{domain}/.well-known/hashi/{local}` | Fetch the hashi document. |
| Redeem | `POST {endpoint}/redeem` | Exchange an offer or short code for a grant. |
| Knock | `POST {endpoint}/knock` | Ask to reach the owner's agent. |
| Poll | `GET {endpoint}/knock/{id}` | Check on a `yeah-nah` knock. |
| Introspect | `POST {endpoint}/introspect` | Optional. Check a credential is still live. |

### 8.1 Request Signing

Every request except Resolve **MUST** be signed with HTTP Message Signatures (RFC 9421), covering at least `@method`, `@target-uri`, `created` and, where there is a body, `content-digest` (RFC 9530). Knocks **MUST** also cover `hashi-grant` and `hashi-delegation` when present.

| Requester | Signs with | Sends |
|-----------|-----------|-------|
| Every requester | Agent key | `Hashi-Delegation`: the agent's delegation JWS |

The verifier **MUST** check that the delegation's `iss` equals the HID of the hashi the requester claims (`requester.hashi` on redeem, `from` on knock), so nobody can redeem or knock in someone else's name. The verifier resolves the requester's hashi document, subject to pinning and freshness, to check the delegation and the `revoked` list.

### 8.2 Redeem

```http
POST /v1/redeem HTTP/1.1
Host: hashi.my.domain
Content-Type: application/hashi+json
Signature-Input: ...
Signature: ...
Hashi-Delegation: eyJ...

{
  "offer": "<offer JWS>",
  "requester": { "hashi": "sarah#example.org" }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `offer` | JWS | One of `offer` or `code` | The offer. |
| `code` | string | One of `offer` or `code` | A short code. |
| `to` | string | With `code` | The hashi the code was issued for. |
| `requester` | object | Yes | `{ "hashi": ... }`: the requester's own hashi. |

The server **MUST**:

1. Check the request signature ([Section 8.1](#81-request-signing)).
2. Check that the offer's `hashi` (or `to`) is a hashi it serves.
3. Verify the offer ([Section 7.1](#71-the-offer-token)) and its expiry.
4. For one-time offers, atomically mark the nonce as used.
5. Record a grant against the requester's HID.

**Response:**

```json
{
  "grant": "<grant JWS>",
  "level": 4
}
```

The grant token is a JWS signed by the server key. It is evidence only; the server's record is authoritative.

```json
{
  "typ": "hashi-grant+jwt",
  "iss": "hid:Q3pT0gq...",
  "sub": "hid:Zr8L...",
  "lvl": 4,
  "iat": 1791270100,
  "gid": "grt_91c..."
}
```

**Who redeems.** An app that redeems on its user's behalf signs with an agent-role delegation, like any requester. "Agent" here means "acts for the user", not "is an AI", so a phone app holds one just as an AI agent does. The app **MUST** show the offer's display name and hashi and get the user's explicit confirmation before redeeming.

### 8.3 Knock

```http
POST /v1/knock HTTP/1.1
Host: hashi.my.domain
Content-Type: application/hashi+json
Signature-Input: ...
Signature: ...
Hashi-Delegation: eyJ...
Hashi-Grant: eyJ...

{
  "to": "john#my.domain",
  "from": "sarah#example.org",
  "intent": "schedule",
  "protocols": ["a2a/1.0"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | Yes | The hashi being knocked. One endpoint may serve many hashis. |
| `from` | string | Yes | The requester's hashi. |
| `intent` | string | No | A routing token matching `^[a-z][a-z0-9-]{0,31}$`. Never free text. Owners **MAY** route to different agents by intent. HASHI gives intents no meaning, and servers **MUST** treat unknown values as absent. |
| `protocols` | string[] | Yes | Supported handover protocols (`name/version`), most preferred first. |

Knocks carry **no** free-text fields. `Hashi-Grant` is optional evidence.

The server **MUST**:

1. Check the request signature and the requester's identity ([Section 8.1](#81-request-signing)).
2. Check that `to` is a hashi it serves.
3. Work out the effective level ([Section 6.3](#63-effective-level)). If it is 0 and level-0 knocks aren't accepted, answer `nah` ([Section 6.4](#64-zero-is-zero)).
4. Apply owner policy for that level, which **MAY** mean asking the owner.
5. Pick the first protocol in the requester's list that the owner's target agent supports.

**Results:**

| HTTP status | `result` | Meaning |
|-------------|----------|---------|
| 200 | `yeah` | Accepted. A handover follows. |
| 202 | `yeah-nah` | Maybe: waiting on the owner. Poll `{endpoint}/knock/{id}` after `retry_after` seconds, signed with the same key. |
| 403 | `nah` | Not accepted. No reason need be given. |
| 406 | `no_common_protocol` | No protocol in common. The owner's protocols are not revealed. |

**Accepted:**

```json
{
  "result": "yeah",
  "level": 4,
  "handover": {
    "protocol": "a2a/1.0",
    "endpoint": "https://agents.my.domain/a2a",
    "credential": "<handover credential>",
    "expires_at": "2026-10-06T07:15:00Z"
  }
}
```

**Waiting on the owner:**

```json
{
  "result": "yeah-nah",
  "id": "knk_5e1...",
  "retry_after": 30
}
```

**Declined:**

```json
{
  "result": "nah"
}
```

A `nah` carries no reason and **MUST** be identical however it was reached, so a requester can't probe the owner's policy or tell they've been singled out.

HASHI has no fallback message channel. If there's no protocol in common, the knock ends at `no_common_protocol`.

### 8.4 Poll

`GET {endpoint}/knock/{id}`, signed by the same key as the original knock. It returns `yeah`, `yeah-nah` or `nah` exactly as in [Section 8.3](#83-knock). A poll signed by any other key gets `nah`. An unknown or expired `id` gets HTTP 404.

### 8.5 Introspect

Optional. An RFC 7662-style check of whether a handover credential is still live. Only agents holding a valid delegation from the **same owner** may call it, and the request **MUST** be signed. Relying on short credential lifetimes instead is fine.

### 8.6 Errors

Problems that aren't decisions return an `error` body, not a `result`:

| HTTP status | When |
|-------------|------|
| 400 | Malformed request. |
| 401 | Missing or invalid signature, delegation or key. |
| 410 | Redeem only: offer or code already used or expired. |
| 429 | Rate limited. Includes `Retry-After`. |

```json
{
  "error": "rate_limited",
  "detail": "Too many requests."
}
```

---

## 9. Handover and Protocol Bindings

### 9.1 The Handover Credential

The credential is whatever the chosen protocol needs to authenticate the requester to the owner's agent. Its exact form is set by the protocol binding. Every binding **MUST** ensure the credential:

- is bound to the requester's key, so it's useless if intercepted;
- names the owner's agent as its audience;
- carries the effective level; and
- expires within 15 minutes. Longer conversations knock again, which re-checks the current level.

What an agent allows at a given level is out of scope.

### 9.2 Binding: `a2a/1.0`

The endpoint is the A2A service URL. The credential is a JWT signed by the owner's server key:

```json
{
  "typ": "hashi-a2a+jwt",
  "iss": "hid:Q3pT0gq...",
  "aud": "https://agents.my.domain/a2a",
  "sub": "hid:Zr8L...",
  "cnf": { "jkt": "<thumbprint of requester key>" },
  "lvl": 4,
  "intent": "schedule",
  "iat": 1791270900,
  "exp": 1791271800,
  "jti": "ses_4d2..."
}
```

- The requester presents it as an HTTP bearer credential and proves possession of the `cnf` key on every request, with an HTTP message signature (RFC 9421) or a DPoP proof (RFC 9449).
- The receiving agent **MUST** verify the JWT against the server key in its owner's binding and **MUST** check `aud`, `exp`, `lvl` and proof of possession.
- The owner's A2A Agent Card advertises the scheme.

### 9.3 Other Bindings

MCP authorisation is built on OAuth 2.1, so a HASHI credential can't simply be handed to an MCP server. An MCP binding, describing how a HASHI grant feeds a conforming OAuth flow, is left for a future document. Other bindings **MAY** be defined separately.

---

## 10. Common Workflows

### 10.1 Coffee After Meeting on the Street

```text
 John's phone          John's HASHI server               Sarah's agent
 (device key)
     |                         |                              |
     |-- QR: offer, lvl 4 ---------------------------------->|
     |                         |<------- 1. resolve hashi ---|
     |                         |-------- hashi document ---->|
     |                         |<------- 2. redeem -----------|
     |                         |-------- grant, level 4 ----->|
               ... that evening ...
     |                         |<------- 3. knock ------------|
     |                         |   check, level 4, a2a/1.0    |
     |                         |-------- 4. yeah + handover ->|
                    John's agent <======= 5. A2A session =======|
```

1. John's phone shows a QR code for `https://my.domain/.well-known/hashi/john` with a level-4 offer in the fragment: one-time, 48-hour expiry, display name "John Doe", note "coffee".
2. Sarah scans it with her HASHI app, or with her camera and taps "Open in app" on John's page. The app shows *John Doe · john#my.domain*, resolves the hashi, checks the chain from John's HID to the device that signed the offer, and on her confirmation redeems it as `sarah#example.org`, signed with its agent delegation. John's server records level 4 for Sarah's HID, and John's phone shows who redeemed it.
3. If Sarah wants John to be able to reach her too, she shows him an offer of her own, at whatever level she chooses.
4. That evening her agent knocks with `intent: "schedule"`. The effective level is 4, John allows scheduling at 4, and the answer is `yeah`, with a 15-minute A2A credential.
5. The agents agree a time over A2A. HASHI's job is done.

### 10.2 New Agent, Same Relationship

A month later Sarah switches agent provider. Her grant is recorded against her HID, so her new agent, with a fresh delegation, knocks at level 4 straight away. No new handshake.

### 10.3 No Hashi? Get One

If Sarah has no HASHI app, her camera opens John's page, which asks *"Got a hashi?"*. She doesn't, so the page points her to an app store or a provider. Once she's set up, she taps the link again and continues as in [Section 10.1](#101-coffee-after-meeting-on-the-street), as long as the offer hasn't expired. Nothing is redeemed until she has a hashi.

### 10.4 Lost Phone

John loses his phone. He uses his identity key, from his laptop's key sync, to revoke the phone's device delegation. His contacts, grants and HID are untouched.

### 10.5 Moving On

John decides he no longer wants to hear from someone. He drops them to 0. He doesn't accept level-0 knocks, so that's the end of it: every future knock from them gets `nah`, the same answer anyone else would get.

---

## 11. Network Security

These rules apply to every URL a HASHI implementation fetches or hands out: hashi documents, `endpoint`, handover endpoints and polling URLs.

- URLs **MUST** use HTTPS.
- Implementations **MUST NOT** follow redirects on any HASHI request.
- Unless the operator explicitly configures otherwise, clients and servers **MUST** refuse to connect to loopback, private, link-local or other non-globally-reachable addresses (RFC 6890). The check **MUST** be made on the resolved address at connection time, so DNS rebinding can't get around it.
- A requester **MUST** reject a handover endpoint whose host is neither the host of the owner's `endpoint` nor listed in `handover_hosts` in the owner's binding.
- Responses larger than 64 KiB **MUST** be rejected.

---

## 12. Security Considerations

| Threat | Mitigation |
|--------|------------|
| **Forgery and tampering** | Offers, grants, delegations, rotations, bindings, freshness statements and credentials are all signed. |
| **Replay** | One-time nonces are burnt on redemption. Signed requests carry `created`; servers **SHOULD** reject signatures older than 5 minutes and keep a short replay cache. Epoch pinning and freshness stop replay of old hashi documents. |
| **Leaked or photographed offers** | Fragment carriage, short expiry and one-time use limit exposure. Owners **MUST** be notified when an offer is redeemed, showing who redeemed it, so a stolen redemption gets noticed on the spot and revoked. |
| **Rogue apps claiming `hashi://`** | QR codes and shared links use the HTTPS form ([Section 7.2](#72-carrying-offers)), and the redeem notification shows the owner who actually redeemed. |
| **Domain or hosting compromise** | Whoever controls `{domain}` can't forge a binding, rotation or delegation, can't roll back the epoch, and can't keep a pre-revocation document alive past the freshness window. First contact relies on trust on first use, unless the requester got a signed offer in person, which pins the HID. |
| **Minting offers for someone else's hashi** | Offers must chain to the HID of the hashi they name ([Section 7.1](#71-the-offer-token)). |
| **Impersonation by display name** | Display names are claims, not identity. Clients show the hashi until a relationship exists, and prefer the user's own contact names after. |
| **Stolen device or agent keys** | Limited by delegation expiry, the `revoked` list, `max_lvl` and role checks. A rotation invalidates all earlier delegations. |
| **Prompt injection** | HASHI carries no conversation content. The only free text is the display name and the offer note, both untrusted display metadata that **MUST NOT** be given to agents as instructions. Knock intents are constrained tokens. High trust says *who* is knocking, not that what they later say is safe to act on. |
| **Server-side request forgery** | See [Section 11](#11-network-security). |
| **Clock skew** | Verifiers **SHOULD** allow up to 60 seconds on `iat`, `exp` and `created`. |

---

## 13. Privacy and Safety

- **The hashi document is public.** It reveals that a hashi exists and, if published, a display name. Servers **SHOULD** rate-limit resolution to make enumeration expensive. Owners **MAY** omit `display_name` and `protocols`.
- **Signalling, not surveillance.** The HASHI server sees who knocks and when, never the agent conversation.
- **A `nah` is just a `nah`.** It carries no reason, and a per-HID refusal looks the same as any other ([Section 6.4](#64-zero-is-zero)).
- **Offers carry only the issuer's own details.**
- **Domain hashis reveal affiliation.** `john#my.domain` tells people where John works. For personal use, a hashi on a provider's domain gives more privacy.
- **Check your devices.** Implementations **SHOULD** let owners list, and revoke in one step, every device, agent and grant, in case someone else set up or still has access to one of them.

---

## 14. IANA Considerations

This specification requests:

- the `hashi` URI scheme (provisional);
- the `hashi` well-known URI suffix;
- the media type `application/hashi+json`;
- the HTTP header fields `Hashi-Delegation` and `Hashi-Grant`; and
- the JWS header parameter `dlg`.

---

## Appendix A: Relationship to Other Protocols

| Protocol | What it does | How HASHI relates |
|----------|--------------|-------------------|
| **WebFinger**, **NIP-05** | Discover information or keys from a human-readable identifier. | Discovery only. No relationship or trust level. |
| **DIDs** | Cryptographic identifiers. | Not a human contact mechanism. An HID could later be expressed as a DID. |
| **A2A** | How agents talk and act after contact. | HASHI supplies the relationship and the credential A2A expects to be obtained separately. |
| **MCP** | Tool and data connectivity, with OAuth-based authorisation. | Not a trust bootstrap from a human address. Binding to come. |
| **Signal, AT Protocol, Matrix** | Keep a person's root key apart from working keys. | Prior art for HASHI's key roles. |

**HASHI:** how I give you an address for me, how much I trust you, and how our software finds a way to talk.

## Appendix B: Open Questions

1. **Introductions:** a signed token by which a mutual contact vouches for a third party, and what level it may confer.
2. **Addressed offers:** a `for` field naming the recipient's HID, so a forwarded link is useless.
3. **Cancelling offers:** revoking outstanding multi-use offers before they expire.
4. **Changing hashi:** moving to a new hashi and telling existing contacts, without telling everyone.
5. **"Got a hashi?" hand-off:** for people with a hashi but no app, John's page asks for their hashi and sends the offer to an `accept` URL published in their hashi document, where their provider asks them to confirm (similar to Mastodon's remote follow).
6. **A slicker two-way exchange** than two separate offers, without giving the server signing power over agents.
7. **MCP binding** via OAuth 2.1.
8. **Recovery short of a reset** when an identity key is lost.
9. **Organisation-level policy** documents.
10. **Expressing an HID as a DID.**

## Appendix C: References

| Reference | Title |
|-----------|-------|
| RFC 2119, RFC 8174 | Key words for use in RFCs to indicate requirement levels |
| RFC 3986 | URI generic syntax |
| RFC 5234 | ABNF |
| RFC 5890 | Internationalised domain names |
| RFC 6890 | Special-purpose IP address registries |
| RFC 7515, 7517, 7518, 7519 | JWS, JWK, JWA, JWT |
| RFC 7638 | JWK thumbprint |
| RFC 7662 | OAuth 2.0 token introspection |
| RFC 7800 | Proof-of-possession key semantics for JWTs |
| RFC 8037 | Ed25519 in JOSE |
| RFC 8615 | Well-known URIs |
| RFC 9110 | HTTP semantics |
| RFC 9421 | HTTP message signatures |
| RFC 9449 | DPoP |
| RFC 9530 | Digest fields |
| Unicode UAX #15 | Normalisation forms |
| [A2A](https://a2a-protocol.org) | Agent2Agent protocol |
| [MCP](https://modelcontextprotocol.io/specification) | Model Context Protocol |
| [DID Core](https://www.w3.org/TR/did-core/) | Decentralised identifiers |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Mapping Nostr keys to DNS identifiers |
| [Signal X3DH](https://signal.org/docs/specifications/x3dh/) | Signal key agreement |
| [AT Protocol](https://atproto.com/specs/did) | DID PLC and rotation keys |
| [Matrix](https://spec.matrix.org/latest/client-server-api/#cross-signing) | Cross-signing |
