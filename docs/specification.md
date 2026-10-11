# HASHI Specification

**Human Agent Secure Handshake Interface**

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
9. [Messages](#9-messages)
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

HASHI is a human relationship and messaging layer for the agentic internet.

People increasingly hand correspondence, scheduling and negotiation to AI agents. Many of those agents run on a phone or laptop: behind NAT, often asleep, never reachable from the internet. Agent-to-agent protocols such as A2A assume both agents can reach each other, and leave credentials to be obtained separately. Nothing defines how a person gives their agents an address others can use, how that person decides who may reach them, how trust formed between two people (say, after meeting on the street) carries across to their agents, or how a message reaches an agent that is offline.

HASHI fills that gap the way an email address and an address book do:

1. A **hashi** is an address you hand out: `john#my.domain`.
2. An **offer**, usually a QR code or link, invites someone in at a trust level.
3. **Redeeming** the offer records a **grant**.
4. Later, the other person's agent **sends** a sealed message to your HASHI server. The server checks who it is and what they're allowed, **stamps** the message with their trust level and puts it in your **inbox**.
5. When one of your agents comes online, it picks the message up, decides whether it's for it, and replies the same way. If both agents can reach each other directly, they **MAY** agree to carry on over A2A or another protocol.

### 1.1 Key Goals

- **People first.** A relationship is between people. Agents, devices, keys, providers and protocols can all change underneath it without breaking it. This is the central invariant of the protocol.
- **Offline first.** Agents only ever connect out, to their own HASHI server. Nobody needs to reach into a phone or laptop.
- **Sealed, not read.** Message content is encrypted end to end to the recipient's agents. The HASHI server checks who is sending, certifies their trust level and queues the message. It can't read it, and it doesn't route it.
- **Open and federated.** Anyone can run a HASHI server, much as anyone can run a mail server, and any conforming app or agent works with any conforming server.
- **Simple to start.** No DNS changes per user, plain HTTPS on port 443, standard JOSE signatures and encryption.
- **Like email, you need an address.** HASHI only connects people who have a hashi. Someone without one can't be reached or use an offer until they get one, so every shared link is also an invitation to get one.

### 1.2 Scope

| In scope | Out of scope |
|----------|--------------|
| Hashi syntax and resolution | What agents say to each other inside a message |
| Identity keys, encryption keys and delegation | The meaning of trust levels 1 to 8 |
| Trust levels, offers and grants | How a HASHI app presents offers, messages and confirmations to its user |
| Sending, stamping and queueing sealed messages | How agents decide which messages are for them |
| Threads and replies | Any protocol agents move to after contact |

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
| **Device key** | A key on one of the owner's devices, delegated by the identity key. Signs offers and manages the inbox. |
| **Server key** | A key held by the HASHI server, delegated through the binding. Signs grants, freshness statements and stamps. |
| **Agent key** | A signing key held by an agent, delegated by the identity key. Signs messages, reply tokens and requests. |
| **Encryption key** | A key-agreement key held by an agent and published in its delegation. Messages to the agent are sealed to it. |
| **HASHI server** | The always-on service that publishes the hashi document, redeems offers and holds the owner's inbox. |
| **Sender** | The agent (an app or AI acting for someone) sending a message. Its owner has a hashi. |
| **Trust level** | An integer from 0 to 9 that one party grants another. Trust is directional. |
| **Offer** | A signed, usually one-time invitation stating the maximum trust level its redeemer may receive. |
| **Grant** | A trust level recorded by a HASHI server for a specific HID. |
| **Message** | A signed request to the recipient's HASHI server carrying a sealed envelope for the recipient's agents. |
| **Envelope** | The end-to-end encrypted, sender-signed content of a message. |
| **Stamp** | The recipient server's signed statement of who sent a message, at what trust level and when. |
| **Inbox** | The owner's two queues on their HASHI server: **incoming** and **processing**. |
| **Thread** | A conversation, named by an ID the first message chooses and every reply repeats. |
| **Reply token** | A token, signed by a sender's agent, that lets one named party reply on one thread. |
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

A hashi with no offer carries no trust. A message sent with only a bare hashi is at level 0. Whether to accept level-0 messages at all is owner policy, and level-0 messages carry no content ([Section 8.3](#83-send)).

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
  "agents": ["<agent delegation JWS>", "<agent delegation JWS>"],
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
| `agents` | JWS[] | Yes | Delegations of the agents that receive the owner's messages ([Section 5.3](#53-delegation-certificates)). New messages are sealed to every agent listed here. |
| `rotations` | JWS[] | Yes | Rotation chain, oldest first. Empty if never rotated. |
| `revoked` | string[] | Yes | `jti` values of revoked, unexpired delegations. |
| `srv_next` | JWK | No | The server key this server will move to. Set by the server and not covered by the binding ([Section 4.6](#46-changing-the-server-key)). |

### 4.3 The Binding

The binding is how the owner, rather than whoever hosts the domain, vouches for everything in the document.

Its payload contains **every field of the document except `binding`, `fresh`, `rotations` and `srv_next`**, plus:

| Field | Description |
|-------|-------------|
| `srv` | The server key (JWK). |
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

- The HASHI server **MUST** serve `fresh`: a JWS signed by the server key with payload `{ "hid", "epoch", "iat" }`, re-signed at least every hour. While the server is changing its key, the payload also carries `srv_next` ([Section 4.6](#46-changing-the-server-key)); other verifiers ignore it.
- Verifiers **MUST** reject a document whose `fresh` is older than 24 hours or whose epoch doesn't match.
- Verifiers **MUST NOT** rely on a cached hashi document older than one hour when deciding a redeem or a send, or when sealing a message.

### 4.6 Changing the Server Key

The binding names one server key, `srv`, and only the owner's identity key can sign a binding, so a server can't change its key on its own. The protocol sets no expiry for it: each server decides when to change its key, for example on a schedule of its own or after a suspected compromise. To change it:

1. The server generates a new key and serves it as `srv_next`, both in the hashi document and inside `fresh`, which its current key signs.
2. When the owner's app sees a `srv_next` inside a `fresh` that verifies with the `srv` of the owner's current binding, it **SHOULD** publish ([Section 8.6](#86-publish)) a new binding whose `srv` is that key. It **MUST** ignore any other `srv_next`. This needs the identity key but no decision from the user, and until the app publishes, the server keeps using its current key.
3. Once that publish is accepted, the server signs freshness statements, stamps and grant tokens with the new key, and stops serving `srv_next`. It **MUST** re-sign the stamps of messages still in the inbox, so the owner's agents can check every stamp against the key in the current binding.
4. The server **MAY** go on accepting grant tokens it signed with its previous key. They are only evidence, and its own records decide ([Section 6.3](#63-effective-level)). A grant token the server doesn't accept is treated as absent, never as a reason for 401 or `nah`.

A new server key **MUST** be newly generated, never a previous key reused.

---

## 5. Keys and Delegation

### 5.1 Algorithms

Signatures use JWS. Implementations **MUST** be able to verify both:

| Algorithm | Curve | Why |
|-----------|-------|-----|
| `EdDSA` | Ed25519 | Compact and widely used. |
| `ES256` | P-256 | What mainstream hardware key stores (Apple Secure Enclave, Android StrongBox) provide. |

Implementations **MAY** sign with either.

Encryption uses JWE (RFC 7516) with key agreement. Implementations **MUST** support:

| Parameter | Value | Why |
|-----------|-------|-----|
| `alg` | `ECDH-ES+A256KW` | Standard JOSE key agreement, one wrapped key per recipient agent. |
| `enc` | `A256GCM` | Authenticated encryption. |
| Curves | X25519 and P-256 | P-256 key agreement is available in phone secure hardware. |

A key **MUST NOT** be used for both signing and encryption.

### 5.2 Key Roles

```text
                  identity key (root, defines the HID)
        ________________|________________________
       |               |              |          |
   binding          device keys    agent keys  rotations
   (server key)        |              |
       |            sign offers,  sign redeems, messages,
  signs grants,     manage inbox  reply tokens, inbox calls;
  fresh, stamps                   each with an encryption key
                                  that opens its messages
```

- The identity key signs **only** the binding, delegations and rotations. It **SHOULD** be kept off everyday devices (for example in platform end-to-end-encrypted key sync, a recovery phrase or a hardware token) and **SHOULD** be reachable from more than one place, because revoking a lost device needs it.
- Device, agent, encryption and server keys **SHOULD** be held in hardware-backed, non-exportable storage where available. Device keys **SHOULD** require a biometric or PIN to sign.
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
  "enc": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "enc" },
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
| `cnf.jwk` | JWK | Yes | The delegated signing public key. |
| `enc` | JWK | Agent only | The agent's encryption public key ([Section 5.1](#51-algorithms)). Required for role `agent`. |
| `max_lvl` | integer | Yes | Agent: highest level it may act at. Device: highest offer level it may sign. |
| `epoch` | integer | Yes | The owner's epoch at issue. |
| `iat`, `exp` | integer | Yes | `exp` **MUST NOT** be more than 90 days after `iat`. Device delegations **SHOULD** be short-lived (for example 30 days). |
| `jti` | string | Yes | Unique ID, used for revocation. |

A verifier **MUST** reject a delegation that:

- is expired, or lasts more than 90 days;
- appears in `revoked`;
- is not signed by the current identity key; or
- has an `epoch` lower than that of the most recent rotation. (A rotation therefore kills every earlier delegation, including any minted with a stolen key.)

Verifiers **MUST** also check `role`: offers **MUST** be signed by a `device` delegation; redeems, messages, reply tokens and inbox claims **MUST** be signed by an `agent` delegation. Listing, releasing and deleting inbox messages, and listing grants, **MAY** be signed by either role ([Section 8.4](#84-the-inbox), [Section 8.7](#87-grants)). Lowering a grant or refusing a HID **MUST** be signed by a `device` delegation.

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
- After rotating, the owner **MUST** publish a new binding signed by the new key and **MUST** reissue delegations, because older ones stop verifying. Reissued agent delegations replace the old ones in `agents`.

### 5.5 Lost or Stolen

| Situation | What happens |
|-----------|--------------|
| **Lost or stolen device** | The owner revokes its delegations and removes any agent on it from `agents` (this needs the identity key, as it changes the binding). Messages already sealed to that agent's encryption key can be read by whoever holds the device, so encryption keys **SHOULD** be non-exportable. Short-lived offers from that device expire on their own, and the delegation's expiry is the backstop until it is revoked. The identity is unaffected. |
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
2. **Belongs to the person.** A grant is recorded against the sender's HID, never an agent or device key, so it survives changes of agent, device or key.
3. **Offer as ceiling.** The server **MUST NOT** record a grant above the offered level, and **MAY** record a lower one.
4. **Lowering is unilateral.** An owner **MAY** lower or revoke a grant at any time.
5. **Raising needs a new offer.** A grant **MUST NOT** be raised except by redeeming a new offer at the higher level.
6. **Prospective only.** Changes apply from the moment they're made. Anything completed under a grant that was valid at the time stays done. Messages already stamped and queued keep the level they were stamped with.
7. **Policy belongs to the owner's software.** Which levels may be offered remotely or in person, on multi-use offers, or with what expiry, is up to the owner's implementation. The protocol only carries the level and enforces it as a ceiling.

### 6.3 Effective Level

When a message arrives, the effective level is the **lowest** of:

- the level the server currently records for the sender (0 if none);
- the level in the presented grant token, if any; and
- the sender's agent delegation `max_lvl`.

The server's record is authoritative, so lowering a grant takes effect at the very next message. A reply token ([Section 9.4](#94-reply-tokens)) lets a reply through but never raises its level.

### 6.4 Zero Is Zero

Dropping someone to 0 puts them back among the strangers. If the owner doesn't accept level-0 messages, the server **MUST** answer `nah`, which makes it a complete block apart from replies the owner's own agents invited with a reply token.

The owner **MAY** refuse specific HIDs, including replies from them. The owner sets this with the grants call ([Section 8.7](#87-grants)). A refusal **MUST** look exactly like any other `nah`, so nobody can tell they've been singled out.

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

All operations are HTTPS requests to the `endpoint` from the relevant hashi document: the recipient's for Redeem and Send, the owner's own for the inbox, Publish and grants.

| Operation | Method and path | Who calls it | Purpose |
|-----------|-----------------|--------------|---------|
| Resolve | `GET https://{domain}/.well-known/hashi/{local}` | Anyone | Fetch the hashi document. |
| Redeem | `POST {endpoint}/redeem` | Another owner's agent | Exchange an offer or short code for a grant. |
| Send | `POST {endpoint}/messages` | Another owner's agent | Deliver a sealed message to the owner's inbox. |
| List | `GET {endpoint}/inbox` | The owner's agents and devices | See what's waiting. |
| Claim | `POST {endpoint}/inbox/{id}/claim` | The owner's agents | Move a message from incoming to processing. |
| Release | `POST {endpoint}/inbox/{id}/release` | The claiming agent, or a device | Put a message back in incoming. |
| Delete | `DELETE {endpoint}/inbox/{id}` | The claiming agent, or a device | Remove a message. |
| Wake | `GET` and `PUT {endpoint}/inbox/wake` | The owner's agents | See and register wake-up channels ([Section 8.5](#85-waking-agents)). |
| Publish | `PUT {endpoint}/document` | The owner's app | Store a new version of the owner's hashi document ([Section 8.6](#86-publish)). |
| List grants | `GET {endpoint}/grants` | The owner's agents and devices | See who the owner has granted a level to, or refused ([Section 8.7](#87-grants)). |
| Lower grant | `PUT {endpoint}/grants/{hid}` | The owner's devices | Lower or remove a grant, or refuse a HID ([Section 8.7](#87-grants)). |

### 8.1 Request Signing

Every request except Resolve and Publish **MUST** be signed with HTTP Message Signatures (RFC 9421), covering at least `@method`, `@target-uri`, `created` and, where there is a body, `content-digest` (RFC 9530). Sends **MUST** also cover `hashi-grant`, `hashi-reply` and `hashi-delegation` when present.

| Caller | Signs with | Sends |
|--------|-----------|-------|
| Every caller | Agent or device key | `Hashi-Delegation`: its delegation JWS |

The verifier **MUST** check that the delegation's `iss` equals the HID of the hashi the caller claims (`requester.hashi` on redeem, `from` on send), so nobody can redeem or send in someone else's name. For inbox and grants operations, the delegation **MUST** belong to the owner of the inbox, which is identified by the delegation's `hashi`. The verifier resolves the caller's hashi document, subject to pinning and freshness, to check the delegation and the `revoked` list.

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
| `requester` | object | Yes | `{ "hashi": ... }`: the redeemer's own hashi. |

The server **MUST**:

1. Check the request signature ([Section 8.1](#81-request-signing)).
2. Check that the offer's `hashi` (or `to`) is a hashi it serves.
3. Verify the offer ([Section 7.1](#71-the-offer-token)) and its expiry.
4. If the owner has refused the redeemer's HID ([Section 8.7](#87-grants)), answer as for an expired offer (410) without marking the nonce as used.
5. For one-time offers, atomically mark the nonce as used.
6. Record a grant against the redeemer's HID.

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

**Who redeems.** An app that redeems on its user's behalf signs with an agent-role delegation, like any sender. "Agent" here means "acts for the user", not "is an AI", so a phone app holds one just as an AI agent does. The app **MUST** show the offer's display name and hashi and get the user's explicit confirmation before redeeming.

### 8.3 Send

```http
POST /v1/messages HTTP/1.1
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
  "thread": "thr_Vb3k9Qx2...",
  "envelope": { "protected": "...", "recipients": [ ... ], "iv": "...", "ciphertext": "...", "tag": "..." },
  "reply_token": "<reply token JWS>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | Yes | The recipient's hashi. One endpoint may serve many hashis. |
| `from` | string | Yes | The sender's hashi. |
| `intent` | string | No | A token matching `^[a-z][a-z0-9-]{0,31}$`. Never free text. Agents **MAY** use it to decide which messages are theirs. HASHI gives intents no meaning. |
| `thread` | string | Yes | The thread ID, matching `^[A-Za-z0-9_-]{16,64}$`. A new thread's ID **MUST** contain at least 128 bits of randomness. Replies repeat it. |
| `envelope` | JWE | See below | The sealed content ([Section 9.1](#91-the-envelope)). |
| `reply_token` | JWS | No | A reply token the sender offers the recipient ([Section 9.4](#94-reply-tokens)). |

`Hashi-Grant` is optional evidence of a grant. `Hashi-Reply` carries a reply token when this message is a reply that the recipient's own agent invited.

Outside the envelope, messages carry **no** free-text fields.

The server **MUST**:

1. Check the request signature and the sender's identity ([Section 8.1](#81-request-signing)).
2. Check that `to` is a hashi it serves.
3. Work out the effective level ([Section 6.3](#63-effective-level)).
4. If `Hashi-Reply` is present, check the reply token ([Section 9.4](#94-reply-tokens)). If it doesn't verify, answer `nah`.
5. If the effective level is 0, there is no valid reply token and the owner doesn't accept level-0 messages, answer `nah` ([Section 6.4](#64-zero-is-zero)).
6. If the owner has refused the sender's HID ([Section 8.7](#87-grants)), answer `nah`. Other owner policy **MAY** also answer `nah`. The server **MUST NOT** hold a message for the owner's approval or route it to a particular agent; that is for the owner's agents and apps.
7. If the effective level is 0 and there is no valid reply token, reject the message with HTTP 400 if it carries an `envelope`. Level-0 messages say who is asking and why (`intent`), and nothing else.
8. Stamp the message ([Section 9.2](#92-the-stamp)) and add it to the owner's incoming queue.

The whole request **MUST NOT** exceed 64 KiB.

**Results:**

| HTTP status | `result` | Meaning |
|-------------|----------|---------|
| 202 | `yeah` | Stamped and queued. This says nothing about whether, or when, an agent will act on it. |
| 403 | `nah` | Not accepted. No reason need be given. |

```json
{
  "result": "yeah",
  "id": "msg_5e1..."
}
```

```json
{
  "result": "nah"
}
```

A `nah` carries no reason and **MUST** be identical however it was reached, so a sender can't probe the owner's policy or tell they've been singled out.

### 8.4 The Inbox

Each owner's inbox has two queues:

- **incoming**: stamped messages no agent has taken yet;
- **processing**: messages an agent has claimed.

The server doesn't route. Every one of the owner's agents sees the same inbox, and each decides for itself what to take, using `intent`, `thread`, whether the envelope is sealed to it, and the stamp.

**List.** `GET {endpoint}/inbox`, signed by one of the owner's agents or devices. It **MAY** be filtered with `queue`, `intent` and `thread` query parameters, and capped with `limit`. Each entry is:

```json
{
  "id": "msg_5e1...",
  "queue": "incoming",
  "stamp": "<stamp JWS>",
  "envelope": { ... },
  "reply_token": "<reply token JWS>",
  "claimed_by": null
}
```

`claimed_by` is the `jti` of the claiming agent's delegation, for messages in processing.

**Claim.** `POST {endpoint}/inbox/{id}/claim`, signed by one of the owner's agents, moves a message from incoming to processing and returns it. The move **MUST** be atomic: only the first claim succeeds, and any other gets HTTP 409.

**Release.** `POST {endpoint}/inbox/{id}/release` moves a message back to incoming. Only the claiming agent or one of the owner's devices may release it, so an owner's app can rescue a message whose agent stopped mid-way.

**Delete.** `DELETE {endpoint}/inbox/{id}` removes a message. Only the claiming agent or one of the owner's devices may delete it. An agent **SHOULD** delete a message once it has dealt with it.

**Retention.** The server **MUST** delete messages, in either queue, that are older than its retention period, which **MUST NOT** exceed 30 days.

### 8.5 Waking Agents

An agent that is online subscribes to its inbox; whenever something is added, the server tells it so. That notice says only that the inbox changed. It **MUST NOT** carry any part of a message, its stamp or its sender, so the notice needs no security of its own and is never trusted. On getting one, the agent lists its inbox over the signed API.

How the notice travels is not fixed by this specification:

- **Listing is the baseline.** Every server and agent **MUST** support List, so polling always works between any app and any server.
- **Wake-up channels are optional.** `GET {endpoint}/inbox/wake` returns the channels the server supports, for example `["webpush"]`. An agent registers one it also supports with `PUT {endpoint}/inbox/wake`, giving `{ "channel": ..., "params": { ... } }`. Channels such as Web Push (RFC 8030), Server-Sent Events, WebSocket or a platform push service are defined separately and **MAY** be added without changing this protocol.

For `webpush`, `params` is the agent's push subscription, and the push message **MUST** have an empty body.

### 8.6 Publish

The owner's app changes its hashi document (display name, `level0`, `agents`, revocations or a rotation) by publishing the whole new document to its own server:

```http
PUT /v1/document HTTP/1.1
Host: hashi.my.domain
Content-Type: application/hashi+json

{ ...the complete hashi document, without "fresh"... }
```

Publish is **self-authorising**. The binding, signed by the identity key, is the authorisation, so the request needs no login, delegation or HTTP signature. The server **MUST** accept the document only if:

1. it verifies as in [Section 4.4](#44-verification-and-pinning), steps 1 and 2;
2. its `hashi` is one this server hosts and its `endpoint` is this server's;
3. the binding's `srv` is this server's current key or its `srv_next` ([Section 4.6](#46-changing-the-server-key)); and
4. if the server already holds a document for that hashi, the new one has the same HID, a higher `epoch`, and a rotation chain that starts with every rotation in the held one.

Because the held document can only be extended, a replayed or older document is always refused. After a rotation, the new identity key alone can publish, even if every delegation has been revoked or has expired.

The server then adds `fresh` ([Section 4.5](#45-freshness)) and serves the new document from Resolve straight away.

**First publish and reset.** When the server holds no document for the hashi, whether it accepts the first one is the server's own registration policy, like an email provider's sign-up rules. A reset ([Section 5.5](#55-lost-or-stolen)) is not done by Publish: rule 4 refuses a new HID while a document is held, so a server that allows resets first drops the held document under its own policy, and the new document is then a first publish. This specification doesn't define either.

| Status | When |
|--------|------|
| 200 | Stored. The body is the document as now served, `fresh` included. |
| 400 | The document is malformed or doesn't verify. |
| 403 | First publish not allowed by this server's policy, or the document isn't for this server (its `hashi`, `endpoint` or binding `srv`). |
| 409 | The epoch isn't higher than the held one, the rotation chain doesn't extend the held one, or the HID differs. |

### 8.7 Grants

The owner manages the grants it has given with two calls, signed like the inbox calls ([Section 8.1](#81-request-signing)) by a delegation belonging to the owner.

**List.** `GET {endpoint}/grants` **MAY** be signed by a device or an agent delegation:

```json
{
  "grants": [
    {
      "hid": "hid:Zr8L...",
      "hashi": "sarah#example.org",
      "level": 4,
      "refused": false,
      "updated": 1791270000
    }
  ]
}
```

`hashi` is the hashi the grantee gave when redeeming or sending, if known. `updated` is when the entry last changed or an offer was last redeemed for it. Refused HIDs are listed with level 0 and `refused: true`. The 64 KiB response limit ([Section 11](#11-network-security)) doesn't apply to this list, which comes from the owner's own server. The owner's app finds out about a new redemption by listing.

**Lower, remove or refuse.** `PUT {endpoint}/grants/{hid}` **MUST** be signed by a **device** delegation, because changing trust is the owner's own decision:

```json
{ "level": 0, "refuse": true }
```

- `level` **MUST NOT** be higher than the recorded one, taking 0 if there is none ([Section 6.2](#62-rules), rule 5). Setting 0 removes the grant.
- `refuse` is optional. `true` refuses that HID from then on and sets its level to 0: its messages, replies included, get `nah` ([Section 6.4](#64-zero-is-zero)), and its redemptions are answered as if the offer had expired. `false` lifts a refusal without granting anything. Leaving it out keeps the current setting.
- Changes apply to the very next request ([Section 6.3](#63-effective-level)).

| Status | When |
|--------|------|
| 200 | Done. The body is the entry as now recorded. |
| 401 | Missing or invalid signature or delegation. |
| 403 | Not the owner's delegation, or an agent delegation tried to change a grant. |
| 409 | `level` is higher than the recorded one. |

Servers **MUST** reject a grants request whose signature `created` is more than 5 minutes old, and **MUST NOT** accept two requests with the same signature base (RFC 9421) within that window.

### 8.8 Errors

Problems that aren't decisions return an `error` body, not a `result`:

| HTTP status | When |
|-------------|------|
| 400 | Malformed request, a level-0 message with an envelope, or a request over 64 KiB. |
| 401 | Missing or invalid signature, delegation or key. |
| 403 | Inbox and grants: the caller isn't one of the owner's agents or devices, or isn't allowed that action. Publish: not allowed by this server's policy, or the document isn't for this server. |
| 404 | Inbox only: no such message. |
| 409 | Claim: already claimed. Publish: the document doesn't extend the held one. Grants: the level would rise. |
| 410 | Redeem only: offer or code already used or expired. |
| 429 | Rate limited. Includes `Retry-After`. |

```json
{
  "error": "rate_limited",
  "detail": "Too many requests."
}
```

---

## 9. Messages

### 9.1 The Envelope

The envelope is a JWE in General JSON Serialization (RFC 7516, Section 7.2.1), using the algorithms in [Section 5.1](#51-algorithms), with one recipient per encryption key it is sealed to. Each recipient's `kid` is the `jti` of that agent's delegation, so an agent can tell whether a message is sealed to it without trying to open it.

- A **new** thread's first message **MUST** be sealed to every agent in the recipient's `agents` list.
- A **reply** **MUST** be sealed only to the agent whose message it answers, using the encryption key in that agent's delegation ([Section 9.3](#93-threads-and-replies)).

Its plaintext is a compact JWS, signed by the sender's agent key, with the agent's delegation in the `dlg` header parameter:

```json
{
  "typ": "hashi-msg+jwt",
  "iss": "hid:Zr8L...",
  "from": "sarah#example.org",
  "to": "john#my.domain",
  "thread": "thr_Vb3k9Qx2...",
  "intent": "schedule",
  "iat": 1791270900,
  "jti": "m_8c2...",
  "body": { "...": "agent-defined content" }
}
```

Signing inside the encryption means the recipient knows who wrote the message even after it has left the server, and the server can't swap one sender's content into another's message. `body` is any JSON value. Its meaning is up to the agents.

An agent opening an envelope **MUST**:

1. Verify the stamp ([Section 9.2](#92-the-stamp)) against the server key in its own owner's binding. If it doesn't verify, re-resolve the owner's hashi document and list the message again ([Section 8.4](#84-the-inbox)), and reject it only if the stamp still doesn't verify ([Section 4.6](#46-changing-the-server-key)).
2. Check that the stamp's `ct` matches the envelope's `ciphertext`.
3. Decrypt, verify the inner JWS, and check that `dlg` chains to the HID in `iss` by resolving `from`.
4. Check that `iss`, `from`, `to`, `thread` and `intent` match the stamp.
5. Discard a `jti` it has already seen from that sender.

The `body` is untrusted input whatever the sender's level. It **MUST NOT** be given to a language model as instructions.

### 9.2 The Stamp

The stamp is how the owner's server certifies a message to the owner's agents. It is a compact JWS signed by the server key:

```json
{
  "typ": "hashi-stamp+jwt",
  "iss": "hid:Q3pT0gq...",
  "sub": "hid:Zr8L...",
  "from": "sarah#example.org",
  "to": "john#my.domain",
  "thread": "thr_Vb3k9Qx2...",
  "intent": "schedule",
  "lvl": 4,
  "reply": false,
  "ct": "<base64url SHA-256 of the envelope's ciphertext>",
  "iat": 1791270901,
  "mid": "msg_5e1..."
}
```

| Field | Description |
|-------|-------------|
| `iss` | The owner's HID. |
| `sub` | The sender's HID. |
| `lvl` | The effective level when the message arrived ([Section 6.3](#63-effective-level)). |
| `reply` | `true` if the message was let through by a reply token. |
| `ct` | Binds the stamp to the envelope. Absent if there is no envelope. |
| `mid` | The inbox message ID. |

The stamp is the only place a trust level reaches the owner's agents. Agents decide what to do at each level, as they do with grants.

### 9.3 Threads and Replies

A conversation is a thread. Its first message picks the thread ID; every reply, in either direction, repeats it, like email's `In-Reply-To`.

To reply, an agent sends a message to the other party's HASHI server, with the same `thread`, sealed only to the agent that wrote the message it answers. That agent finds the reply by its thread, and nobody else can open it. The other party's server checks the reply like any other message: either the replier has a grant there, or it presents a reply token.

### 9.4 Reply Tokens

Trust is directional, so the person you write to may have no grant on your server. A reply token lets them answer anyway, on that one thread.

A reply token is a compact JWS, signed by the sender's agent key, with its delegation in `dlg`:

```json
{
  "typ": "hashi-reply+jwt",
  "iss": "hid:Zr8L...",
  "hashi": "sarah#example.org",
  "sub": "hid:Q3pT0gq...",
  "thread": "thr_Vb3k9Qx2...",
  "iat": 1791270900,
  "exp": 1791875700,
  "jti": "rpl_2a7..."
}
```

- `sub` is the HID of the one party who may reply; `thread` is the one thread.
- `exp` **MUST NOT** be more than 30 days after `iat`.
- The sender offers it in `reply_token`; the recipient's agents present it, unchanged, in `Hashi-Reply` on their replies.

The server receiving a reply **MUST** check that the token's `dlg` is a current `agent` delegation from the owner it serves, that `hashi` is the `to` hashi, that `sub` is the sender's HID, that `thread` matches, and that it hasn't expired. A valid token lets the reply into the inbox at the sender's own effective level, which may be 0, with `reply: true` in the stamp. The owner can withdraw outstanding tokens by revoking the agent's delegation.

### 9.5 Moving to Another Protocol

Agents that can reach each other directly **MAY** agree, inside their messages, to carry on over A2A or another protocol. HASHI doesn't define how. When they do, they **SHOULD** authenticate each other with keys that chain to their HASHI identities, for example by signing requests with their agent keys (RFC 9421), so the people behind them stay the people HASHI checked.

---

## 10. Common Workflows

### 10.1 Coffee After Meeting on the Street

```text
 John's phone     John's HASHI server     Sarah's agent     Sarah's HASHI server
 (device key)
     |                    |                     |                    |
     |-- QR: offer, lvl 4 ------------------->|                    |
     |                    |<-- 1. resolve ------|                    |
     |                    |<-- 2. redeem -------|                    |
     |                    |--- grant, lvl 4 --->|                    |
               ... that evening ...
     |                    |<-- 3. send ---------|                    |
     |                    |  stamp lvl 4, queue |                    |
 John's laptop agent (wakes up later)            |                    |
     |<-- 4. list, claim -|                     |                    |
     |-------------------------- 5. reply, with Hashi-Reply -------->|
     |                    |                     |<-- 6. list, claim -|
```

1. John's phone shows a QR code for `https://my.domain/.well-known/hashi/john` with a level-4 offer in the fragment: one-time, 48-hour expiry, display name "John Doe", note "coffee".
2. Sarah scans it with her HASHI app, or with her camera and taps "Open in app" on John's page. The app shows *John Doe · john#my.domain*, resolves the hashi, checks the chain from John's HID to the device that signed the offer, and on her confirmation redeems it as `sarah#example.org`, signed with its agent delegation. John's server records level 4 for Sarah's HID, and John's phone shows who redeemed it.
3. That evening her agent sends John a message with `intent: "schedule"` and a new thread, sealed to each agent in John's `agents` list, and offers John a reply token. John's server checks her signature and grant, stamps the message at level 4 and queues it. Her agent gets `yeah` and goes back to sleep.
4. Later, John's laptop agent comes online, or is woken by a push. It lists the inbox, sees a scheduling message sealed to it, claims it, checks the stamp and Sarah's signature, and opens it.
5. It replies to Sarah's server on the same thread, sealed only to the agent that wrote to it, presenting Sarah's reply token. John has no grant from Sarah, but the token lets the reply in.
6. Sarah's agent finds the reply by its thread. The agents go back and forth until a time is agreed, then delete the messages.

If Sarah wants John to be able to start conversations with her too, she shows him an offer of her own, at whatever level she chooses.

### 10.2 New Agent, Same Relationship

A month later Sarah switches agent provider. Her grant is recorded against her HID, so her new agent, with a fresh delegation, sends at level 4 straight away. No new handshake.

### 10.3 No Hashi? Get One

If Sarah has no HASHI app, her camera opens John's page, which asks *"Got a hashi?"*. She doesn't, so the page points her to an app store or a provider. Once she's set up, she taps the link again and continues as in [Section 10.1](#101-coffee-after-meeting-on-the-street), as long as the offer hasn't expired. Nothing is redeemed until she has a hashi.

### 10.4 Lost Phone

John loses his phone. He uses his identity key, from his laptop's key sync, to revoke the phone's device delegation and remove the phone's agent from `agents`. New messages are no longer sealed to it. His contacts, grants and HID are untouched.

### 10.5 Moving On

John decides he no longer wants to hear from someone. He drops them to 0. He doesn't accept level-0 messages, so that's the end of it: every future message from them gets `nah`, the same answer anyone else would get.

---

## 11. Network Security

These rules apply to every URL a HASHI implementation fetches or hands out: hashi documents, `endpoint` and wake-up channel URLs such as push subscriptions.

- URLs **MUST** use HTTPS.
- Implementations **MUST NOT** follow redirects on any HASHI request.
- Unless the operator explicitly configures otherwise, clients and servers **MUST** refuse to connect to loopback, private, link-local or other non-globally-reachable addresses (RFC 6890). The check **MUST** be made on the resolved address at connection time, so DNS rebinding can't get around it.
- Responses and requests larger than 64 KiB **MUST** be rejected. Responses from the owner's own server to its inbox and grants calls are exempt ([Section 8.4](#84-the-inbox), [Section 8.7](#87-grants)), so a full-size message can always be listed and claimed.

Agents never need to accept inbound connections. They only connect out, to HASHI servers.

---

## 12. Security Considerations

| Threat | Mitigation |
|--------|------------|
| **Forgery and tampering** | Offers, grants, delegations, rotations, bindings, freshness statements, stamps, reply tokens and messages are all signed. |
| **The server reading or altering messages** | Envelopes are encrypted end to end to the recipient's agents and signed inside by the sender's agent. The stamp binds the server's certificate to the ciphertext. |
| **The server lying about trust** | The owner's server is trusted to certify levels to the owner's own agents, just as it is trusted to keep the owner's grants. It can't forge content or a sender's signature. |
| **Replay** | One-time nonces are burnt on redemption. Signed requests carry `created`; servers **SHOULD** reject signatures older than 5 minutes and keep a short replay cache, and **MUST** do so for the grants calls ([Section 8.7](#87-grants)). Agents discard repeated message `jti` values. Epoch pinning and freshness stop replay of old hashi documents. |
| **Spam and inbox flooding** | Only senders with a grant, or with a reply token from one of the owner's agents, can put content in an inbox. Level-0 messages carry no content. Messages are capped at 64 KiB, servers rate-limit per sender, and retention is at most 30 days. |
| **Leaked or photographed offers** | Fragment carriage, short expiry and one-time use limit exposure. Owners **MUST** be notified when an offer is redeemed, showing who redeemed it, so a stolen redemption gets noticed on the spot and revoked. |
| **Rogue apps claiming `hashi://`** | QR codes and shared links use the HTTPS form ([Section 7.2](#72-carrying-offers)), and the redeem notification shows the owner who actually redeemed. |
| **Domain or hosting compromise** | Whoever controls `{domain}` can't forge a binding, rotation or delegation, can't roll back the epoch, and can't keep a pre-revocation document alive past the freshness window. They can't add an encryption key to `agents`, because the binding covers it. First contact relies on trust on first use, unless the sender got a signed offer in person, which pins the HID. |
| **Minting offers for someone else's hashi** | Offers must chain to the HID of the hashi they name ([Section 7.1](#71-the-offer-token)). |
| **Impersonation by display name** | Display names are claims, not identity. Clients show the hashi until a relationship exists, and prefer the user's own contact names after. |
| **Stolen device or agent keys** | Limited by delegation expiry, the `revoked` list, `max_lvl` and role checks. A rotation invalidates all earlier delegations. A stolen agent's encryption key opens messages already sealed to it, so removing it from `agents` quickly matters. |
| **Prompt injection** | Message bodies are untrusted input at every level and **MUST NOT** be given to a language model as instructions. Outside the envelope, the only free text is the display name and the offer note, both untrusted display metadata. Intents are constrained tokens. High trust says *who* sent a message, not that what it says is safe to act on. |
| **Server-side request forgery** | See [Section 11](#11-network-security). |
| **Clock skew** | Verifiers **SHOULD** allow up to 60 seconds on `iat`, `exp` and `created`. |

---

## 13. Privacy and Safety

- **The hashi document is public.** It reveals that a hashi exists, how many agents receive messages and, if published, a display name. Servers **SHOULD** rate-limit resolution to make enumeration expensive. Owners **MAY** omit `display_name`.
- **Sealed, not read.** The HASHI server sees who sends to whom, when, the intent, the thread and the size. It never sees message content. Servers **SHOULD** keep that metadata no longer than the messages themselves.
- **Wake-ups say nothing.** A wake-up notice carries no part of a message, so push services learn only that something changed.
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
- the HTTP header fields `Hashi-Delegation`, `Hashi-Grant` and `Hashi-Reply`; and
- the JWS header parameter `dlg`.

---

## Appendix A: Relationship to Other Protocols

| Protocol | What it does | How HASHI relates |
|----------|--------------|-------------------|
| **Email (SMTP, IMAP, JMAP)** | Store-and-forward messaging between independent providers. | The model HASHI follows: your server holds messages until your software picks them up. JMAP's optional push over a polling baseline is the model for waking agents. |
| **DIDComm v2** | Encrypted agent messaging, with mediators that hold messages for offline agents. | Prior art for HASHI's sealed, sender-signed envelopes and for picking messages up from an always-on server. |
| **Nostr** | Signed events held by relays that clients subscribe to. | Prior art for a simple server that stores and serves but doesn't route. |
| **WebFinger**, **NIP-05** | Discover information or keys from a human-readable identifier. | Discovery only. No relationship or trust level. |
| **DIDs** | Cryptographic identifiers. | Not a human contact mechanism. An HID could later be expressed as a DID. |
| **A2A** | How agents talk and act when both can reach each other. | Agents **MAY** move to A2A after contact, authenticating with their HASHI keys ([Section 9.5](#95-moving-to-another-protocol)). HASHI works when one of them can't be reached. |
| **MCP** | Tool and data connectivity, with OAuth-based authorisation. | Not a trust bootstrap from a human address. |
| **Signal, AT Protocol, Matrix** | Keep a person's root key apart from working keys. | Prior art for HASHI's key roles. |

**HASHI:** how I give you an address for me, how much I trust you, and how our agents reach each other even when they're offline.

## Appendix B: Open Questions

1. **Introductions:** a signed token by which a mutual contact vouches for a third party, and what level it may confer.
2. **Addressed offers:** a `for` field naming the recipient's HID, so a forwarded link is useless.
3. **Cancelling offers:** revoking outstanding multi-use offers before they expire.
4. **Changing hashi:** moving to a new hashi and telling existing contacts, without telling everyone.
5. **"Got a hashi?" hand-off:** for people with a hashi but no app, John's page asks for their hashi and sends the offer to an `accept` URL published in their hashi document, where their provider asks them to confirm (similar to Mastodon's remote follow).
6. **A slicker two-way exchange** than two separate offers, without giving the server signing power over agents.
7. **Profiles for moving to A2A or MCP** using HASHI agent keys.
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
| RFC 7515, 7516, 7517, 7518, 7519 | JWS, JWE, JWK, JWA, JWT |
| RFC 7638 | JWK thumbprint |
| RFC 7800 | Proof-of-possession key semantics for JWTs |
| RFC 8037 | Ed25519 and X25519 in JOSE |
| RFC 8030 | Generic event delivery using HTTP push (Web Push) |
| RFC 8615 | Well-known URIs |
| RFC 9110 | HTTP semantics |
| RFC 9421 | HTTP message signatures |
| RFC 9530 | Digest fields |
| Unicode UAX #15 | Normalisation forms |
| [A2A](https://a2a-protocol.org) | Agent2Agent protocol |
| [MCP](https://modelcontextprotocol.io/specification) | Model Context Protocol |
| [DID Core](https://www.w3.org/TR/did-core/) | Decentralised identifiers |
| [DIDComm Messaging v2](https://identity.foundation/didcomm-messaging/spec/v2.1/) | Encrypted agent messaging and mediators |
| [JMAP](https://www.rfc-editor.org/rfc/rfc8620) | RFC 8620, including its push model |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Mapping Nostr keys to DNS identifiers |
| [Signal X3DH](https://signal.org/docs/specifications/x3dh/) | Signal key agreement |
| [AT Protocol](https://atproto.com/specs/did) | DID PLC and rotation keys |
| [Matrix](https://spec.matrix.org/latest/client-server-api/#cross-signing) | Cross-signing |
