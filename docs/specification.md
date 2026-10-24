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
2. An **offer**, usually a QR code or link, invites someone in.
3. **Redeeming** the offer records a **grant**, once you confirm who redeemed it and pick their trust level. The redeemer normally offers one back, so confirming them connects you both ways.
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
| Signing up, and resets without the identity key | Which checks a server runs before someone signs up |

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
| **Identity key** | The owner's root signing key. Signs the binding, delegations, rotations and the owner's rules, and nothing else. |
| **Device key** | A key on one of the owner's devices, delegated by the identity key. Signs offers and redeems other people's, confirms grants and manages the inbox. |
| **Server key** | A key held by the HASHI server, delegated through the binding. Signs freshness statements and stamps. |
| **Agent key** | A signing key held by an agent, delegated by the identity key. Signs messages, reply tokens and requests. |
| **Encryption key** | A key-agreement key held by an agent and published in its delegation. The agent's copy of the inbox key is sealed to it. |
| **Inbox key** | A key-agreement key that belongs to the hashi rather than to any one agent. Every message to the owner is sealed to it, and each of the owner's agents holds a copy. |
| **HASHI server** | The always-on service that publishes the hashi document, handles redemptions and holds the owner's inbox. |
| **Sender** | The agent (an app or AI acting for someone) sending a message. Its owner has a hashi. |
| **Trust level** | An integer from 0 to 9 that one party grants another. Trust is directional. |
| **Offer** | A signed, usually one-time invitation. Redeeming it asks the owner for a grant. |
| **Grant** | A trust level recorded by a HASHI server for a specific HID. |
| **Owner's rules** | The owner's statement of what their agents may do for someone at each trust level, signed by the identity key and sealed to the inbox key. |
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

A short link ([Section 7.3](#73-short-links)) is different: `https://my.domain/h/K7q2mX9pTzR4wB1c`, or `hashi://my.domain/h/K7q2mX9pTzR4wB1c` inside an app, stands for one offer and names no hashi. Its path has two segments, so it can't be mistaken for a hashi's.

### 3.3 Bare Hashis

A hashi with no offer carries no trust. A message sent with only a bare hashi is at level 0. Whether to accept level-0 messages at all is owner policy, and an owner who does gets only short ones ([Section 8.3](#83-send)).

> The hashi identifies and locates. Offers and grants authorise.

### 3.4 Display Names

An owner **MAY** publish a display name in the hashi document and **MAY** include one in offers.

- A display name **MUST NOT** be used for authentication, trust decisions, HID derivation, uniqueness or equality. Two people can both be called John Smith.
- Display names **MUST** be normalised to Unicode NFC, **MUST NOT** contain control, format or bidirectional-override characters (Unicode categories Cc and Cf), and **MUST NOT** exceed 128 characters. Clients **MUST** apply the same rules before display, and **MUST** reject or strip non-conforming values.
- Until the user has saved the other party as a contact, or granted them a level above 0, clients **MUST** show the hashi alongside any display name, never the name alone. Redeeming *their* offer doesn't count, because they control that step, and neither does the grant your app makes when they redeem the offer you sent back ([Section 8.7](#87-grants)).
- Once a contact is saved, clients **SHOULD** prefer the user's own name for it.
- Owners **MAY** leave the display name out of the public document and supply it only in offers.

```text
John Doe          ← who a person sees
john#my.domain    ← the address
hid:Q3pT0gq...    ← the cryptographic identity
```

### 3.5 Pictures

An owner **MAY** publish a picture, such as a photo or a company logo, in the hashi document, so that people who already know them can recognise them. It's a link to the image and the image's hash:

```json
"picture": {
  "url": "https://pictures.my.domain/q4X2...webp",
  "sha256": "<base64url SHA-256 of the image file>"
}
```

- Like a display name ([Section 3.4](#34-display-names)), a picture **MUST NOT** be used for authentication, trust decisions or equality. A company's logo is exactly what an impersonator would copy, and only the hashi's domain shows which organisation it belongs to.
- The image **MUST** be a square JPEG, PNG or WebP, no more than 256 pixels on a side and no more than 48 KiB. SVG isn't allowed, because it can carry script. Apps **SHOULD** re-encode an image and drop its metadata, such as where a photo was taken, before publishing it.
- `sha256` is the SHA-256 hash of the image file's bytes, in base64url without padding. The binding covers it ([Section 4.3](#43-the-binding)), so only the owner can change the picture. Whoever hosts the image can stop serving it, but can't swap it. Clients **MUST NOT** show an image that doesn't match the hash or breaks the rules above, and **SHOULD** check its size and dimensions before decoding it. They **MAY** keep it, keyed by its hash, for as long as they like.
- The image can be on any host, subject to [Section 11](#11-network-security). Loading it tells that host that someone is looking, and when, as a tracking pixel does in an email. So clients **MUST NOT** load or show anyone else's picture until the user has saved them as a contact or granted them a level above 0.
- Owners **MAY** leave it out. Like the display name, it's public.

**Storing a picture.** The owner's server **MAY** host pictures for its hashis. The app sends the image file in a request signed by a `device` delegation of one of those hashis:

```http
POST /v1/pictures HTTP/1.1
Host: hashi.my.domain
Content-Type: image/webp
Content-Digest: sha-256=:...:
Signature-Input: ...
Signature: ...
Hashi-Delegation: eyJ...

<the image file>
```

The server works out the file's format from its first bytes, checks its size and dimensions, and answers 400 if it breaks the rules above. It stores the image where clients can load it under [Section 11](#11-network-security), served with that format's content type, and answers 200 with the value for `picture`:

```json
{ "url": "https://pictures.my.domain/q4X2...webp", "sha256": "q4X2..." }
```

Storing a picture doesn't change the document. The app checks that `sha256` is the hash of the file it sent, then publishes a document that names it ([Section 8.6](#86-publish)). The server decides how long to keep a picture that the published document doesn't name. A server that doesn't host pictures answers 404.

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
- The server **MUST** answer 404 for a hashi it doesn't hold.
- Responses larger than 64 KiB **MUST** be rejected.

### 4.2 The Hashi Document

```json
{
  "version": "0.1",
  "hashi": "john#my.domain",
  "display_name": "John Doe",
  "picture": { "url": "https://pictures.my.domain/q4X2...webp", "sha256": "q4X2..." },
  "hid": "hid:Q3pT0gq1mRk2b0nN7y3A5xYv9L6cF8hJ2sW4eD1uK0o",
  "epoch": 3,
  "identity_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "binding": "<JWS signed by identity key>",
  "fresh": "<JWS signed by server key>",
  "endpoint": "https://hashi.my.domain/v1",
  "level0": { "accept": false },
  "agents": ["<agent delegation JWS>", "<agent delegation JWS>"],
  "inbox_key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "enc", "kid": "Hq4c..." },
  "inbox_key_copies": { "protected": "...", "recipients": [ ... ], "iv": "...", "ciphertext": "...", "tag": "..." },
  "rotations": [],
  "revoked": ["dlg_1b9..."]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Protocol version. |
| `hashi` | string | Yes | Canonical hashi. |
| `display_name` | string | No | Presentation only ([Section 3.4](#34-display-names)). |
| `picture` | object | No | `{ "url", "sha256" }`. A picture of the owner, for presentation only ([Section 3.5](#35-pictures)). |
| `hid` | string | Yes | `hid:` plus the base64url JWK thumbprint (RFC 7638) of the owner's genesis identity key. |
| `epoch` | integer | Yes | Incremented on every signed change, including every revocation and rotation. |
| `identity_key` | JWK | Yes | The owner's current identity public key. |
| `binding` | JWS | Yes | Signed by the identity key ([Section 4.3](#43-the-binding)). |
| `fresh` | JWS | Yes | Freshness statement signed by the server key ([Section 4.5](#45-freshness)). |
| `endpoint` | URL | Yes | HTTPS base URL of the HASHI server API. May be on a different host from `{domain}`. |
| `level0` | object | No | `{ "accept": boolean }`. Default `false`. `true` lets strangers send short messages ([Section 8.3](#83-send)). |
| `agents` | JWS[] | Yes | Delegations of the owner's agents, each app's own agent included ([Section 5.3](#53-delegation-certificates)). Each gets a copy of the inbox key. |
| `inbox_key` | JWK | Yes | The public half of the inbox key. Every message to the owner is sealed to it ([Section 9.1](#91-the-envelope)). |
| `inbox_key_copies` | JWE | Yes | The private inbox keys, sealed to each agent in `agents` ([Section 9.1](#91-the-envelope)). |
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

- The HASHI server **MUST** serve `fresh`: a JWS signed by the server key with payload `{ "hid", "epoch", "iat" }`, re-signed at least every hour. While the server is changing its key, the payload also carries `srv_next` ([Section 4.6](#46-changing-the-server-key)); other verifiers ignore it. While a reset or deletion started without the identity key is waiting to happen ([Section 8.6](#86-publish)), the payload also carries `reset`: `{ "hashi": ..., "action": "reset" | "delete", "hid": ..., "at": ... }`. `hid` is the new HID a reset will hand the name to, and `at` is the earliest time the server may go ahead, in seconds since the epoch. The hashi is named because one HID can hold several hashis on a server. Nothing about the sign-up account goes in.
- Verifiers **MUST** reject a document whose `fresh` is older than 24 hours or whose epoch doesn't match.
- Verifiers **MUST NOT** rely on a cached hashi document older than one hour when deciding a redeem or a send, or when sealing a message.

### 4.6 Changing the Server Key

The binding names one server key, `srv`, and only the owner's identity key can sign a binding, so a server can't change its key on its own. The protocol sets no expiry for it: each server decides when to change its key, for example on a schedule of its own or after a suspected compromise. To change it:

1. The server generates a new key and serves it as `srv_next`, both in the hashi document and inside `fresh`, which its current key signs.
2. When the owner's app sees a `srv_next` inside a `fresh` that verifies with the `srv` of the owner's current binding, it **SHOULD** publish ([Section 8.6](#86-publish)) a new binding whose `srv` is that key. It **MUST** ignore any other `srv_next`. This needs the identity key but no decision from the user, and until the app publishes, the server keeps using its current key.
3. Once that publish is accepted, the server signs freshness statements and stamps with the new key, and stops serving `srv_next`. It **MUST** re-sign the stamps of messages still in the inbox, so the owner's agents can check every stamp against the key in the current binding.

A new server key **MUST** be newly generated, never a previous key reused.

### 4.7 The Server Document

An app that knows only a domain, because someone typed it or picked it from a list, learns about that domain's HASHI server from the server document:

```http
GET /.well-known/hashi HTTP/1.1
Host: {domain}
Accept: application/hashi+json
```

```json
{
  "version": "0.1",
  "endpoint": "https://hashi.my.domain/v1",
  "srv": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "signup": "https://my.domain/signup",
  "account": "https://my.domain/account"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Protocol version. |
| `endpoint` | URL | Yes | The `endpoint` that hashi documents on this domain use. |
| `srv` | JWK | Yes | The server key, which a first binding names ([Section 4.3](#43-the-binding)). |
| `signup` | URL | No | The sign-up page ([Section 8.6](#86-publish)). Left out if the server has none. |
| `account` | URL | No | Where people manage their account with this server: terms, privacy and deleting their hashi. |

No hashi can have this path, because every hashi's path has a name after `hashi/`. The rules for Resolve apply: HTTPS on the default port, no redirects, and nothing over 64 KiB.

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
| `alg` | `ECDH-ES+A256KW` | Standard JOSE key agreement, one wrapped key per recipient. |
| `enc` | `A256GCM` | Authenticated encryption. |
| Curves | X25519 and P-256 | P-256 key agreement is available in phone secure hardware. |

A recipient **MUST** validate a JWE's `epk` against the curve of its own key before using it (RFC 8725, Section 3.4). A JWE **MUST NOT** use `zip`, and a recipient **MUST** reject one that does. A key **MUST NOT** be used for both signing and encryption.

### 5.2 Key Roles

```text
                  identity key (root, defines the HID)
        ________________|________________________________________
       |               |              |          |              |
   binding          device keys    agent keys  rotations  owner's rules
   (server key)        |              |
       |            sign offers,  sign messages,
  signs fresh,      redeems;      reply tokens, inbox calls;
  stamps            manage inbox  each with an encryption key
                                  that opens the inbox key
```

- The identity key signs **only** the binding, delegations, rotations and the owner's rules ([Section 8.8](#88-owners-rules)). It **SHOULD** be kept off everyday devices (for example in platform end-to-end-encrypted key sync, a recovery phrase or a hardware token) and **SHOULD** be reachable from more than one place, because revoking a lost device needs it.
- Device, agent, encryption and server keys **SHOULD** be held in hardware-backed, non-exportable storage where available. The inbox key can't be, because the owner's app copies it to each agent ([Section 9.1](#91-the-envelope)). Device keys **SHOULD** require a biometric or PIN to sign.
- The identity key **MUST NOT** be given to the HASHI server or to any agent. A device key **MUST NOT** be usable by an agent, even one built into the owner's app, because a device's signature is how a server knows a person is acting ([Section 8.2](#82-redeem)).

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
| `max_lvl` | integer | Yes | Agent: highest level it may act at. Device: highest level it may raise a grant to. |
| `epoch` | integer | Yes | The owner's epoch at issue. |
| `iat`, `exp` | integer | Yes | `exp` **MUST NOT** be more than 90 days after `iat`. Device delegations **SHOULD** be short-lived (for example 30 days). |
| `jti` | string | Yes | Unique ID, used for revocation. |

A verifier **MUST** reject a delegation that:

- is expired, or lasts more than 90 days;
- appears in `revoked`;
- is not signed by the current identity key; or
- has an `epoch` lower than that of the most recent rotation. (A rotation therefore kills every earlier delegation, including any minted with a stolen key.)

Verifiers **MUST** also check `role`: offers, redeems and redeem status requests **MUST** be signed by a `device` delegation ([Section 8.2](#82-redeem)); messages, reply tokens and inbox claims **MUST** be signed by an `agent` delegation. Listing, releasing and deleting inbox messages, listing grants and fetching the owner's rules **MAY** be signed by either role ([Section 8.4](#84-the-inbox), [Section 8.7](#87-grants), [Section 8.8](#88-owners-rules)). Storing an offer ([Section 7.3](#73-short-links)), a picture ([Section 3.5](#35-pictures)) or the owner's rules, confirming or lowering a grant, or refusing a HID, **MUST** be signed by a `device` delegation.

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
| **Lost or stolen device** | The owner revokes its delegations and removes any agent on it from `agents`, which also replaces the inbox key ([Section 9.1](#91-the-envelope)). This needs the identity key, as it changes the binding. Whoever holds the device can open messages sealed to the old inbox key. Short-lived offers from that device expire on their own, and the delegation's expiry is the backstop until it is revoked. The identity is unaffected. |
| **Identity key compromised, still in the owner's hands** | Rotate to a new key and revoke everything. |
| **Identity key lost, or an attacker may have rotated first** | Reset: a new identity key and therefore a new HID. Contacts see a new identity, trust drops to 0, and the owner shares fresh offers. Whoever holds the current identity key can block a reset of the same name ([Section 8.6](#86-publish)), so if an attacker has it, the owner has to start a new hashi, which is always possible. |

---

## 6. Trust Levels

### 6.1 Scale

| Level | Meaning |
|-------|---------|
| **0** | Public. No proof needed. The default for bare hashis and strangers. |
| **1–8** | Ordered, owner-defined. Higher means more trusted. |
| **9** | Highest trust. |

Only 0 and 9 have protocol-defined meanings. Implementations decide what 1 to 8 unlock and **SHOULD** let owners configure it. An owner can keep what each level allows on their HASHI server, for their agents to follow ([Section 8.8](#88-owners-rules)).

### 6.2 Rules

1. **Directional.** Each party sets only the level it grants the other. Redeeming an offer can give the redeemer a grant, once the owner confirms it, and gives the offer's issuer nothing. To trust someone back, issue your own offer. The redeemer's app normally sends one with the redemption ([Section 8.2](#82-redeem)).
2. **Belongs to the person.** A grant is recorded against the sender's HID, never an agent or device key, so it survives changes of agent, device or key.
3. **The owner picks the level.** An offer names no level, since a level means something only to the owner's own agents. The owner picks one when confirming whoever redeemed it ([Section 8.7](#87-grants)).
4. **Lowering is unilateral.** An owner **MAY** lower or revoke a grant at any time.
5. **Raising needs an offer and a confirm.** A grant **MUST NOT** be raised except by redeeming an offer, and then only once the owner confirms it from a device ([Section 8.7](#87-grants)). Until then the redemption is pending and the old level applies.
6. **Prospective only.** Changes apply from the moment they're made. Anything completed under a grant that was valid at the time stays done. Messages already stamped and queued keep the level they were stamped with.
7. **Policy belongs to the owner's software.** The owner's implementation decides which levels to suggest or allow for offers made remotely, in person or for many people, and how long offers last.

### 6.3 Effective Level

When a message arrives, the effective level is the **lower** of:

- the level the server currently records for the sender (0 if none); and
- the sender's agent delegation `max_lvl`.

Lowering a grant therefore takes effect at the very next message. A reply token ([Section 9.4](#94-reply-tokens)) lets a reply through but never raises its level.

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
| `nonce` | string | Yes | **MUST** contain at least 128 bits of randomness. |
| `one_time` | boolean | Yes | One-time offers **MUST** be accepted at most once. |
| `iat`, `exp` | integer | Yes | One-time offers **SHOULD** expire within 48 hours. |
| `note` | string | No | Up to 140 characters of untrusted display text, normalised like display names. **MUST NOT** be passed to an agent or language model as instructions. |

Multi-use offers (say, one printed on a business card) are allowed.

**Verifying an offer.** A verifier **MUST** resolve the offer's `hashi` and check that:

- the offer's `iss`, the `dlg` delegation's `iss` and the resolved document's `hid` are all equal;
- the delegation's `hashi` equals the offer's `hashi`; and
- the delegation verifies against that document's identity key and has role `device`.

A HASHI server handling a redemption **MUST** apply these checks against its own record of the hashi, so nobody can mint offers for a hashi they don't own. Redeemers **MUST** use the `endpoint` from the verified hashi document.

### 7.2 Carrying Offers

An offer is a capability: anyone holding it can redeem it, though nothing changes until the owner confirms who did. It therefore travels in the URI **fragment**, which is never sent to a server and so stays out of server logs, browser history, Referer headers and link-preview bots.

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

### 7.3 Short Links

A whole offer makes a dense QR code and a long link, which some chat apps cut short. A server **MAY** therefore hold an offer for its owner and give back a code for a **short link** on the hashi's domain:

```text
https://my.domain/h/K7q2mX9pTzR4wB1c
```

**Storing an offer.** The owner's app sends the signed offer to its own server:

```http
POST /v1/offers HTTP/1.1
Host: hashi.my.domain
Content-Type: application/hashi+json
Signature-Input: ...
Signature: ...
Hashi-Delegation: eyJ...

{ "offer": "<offer JWS>" }
```

The request **MUST** be signed by a `device` delegation of the hashi the offer is for. The server verifies the offer and its expiry as Redeem does ([Section 7.1](#71-the-offer-token)), answers 400 if either check fails, and otherwise answers 200 with a new code:

```json
{ "code": "K7q2mX9pTzR4wB1c" }
```

The server **MUST** choose each code at random: 16 letters and digits (A-Z, a-z, 0-9), about 95 bits, so nobody can guess one. A short link works only until someone first redeems its offer, even a multi-use one. An attempt from a refused HID ([Section 8.7](#87-grants)) stops it too, so the link can't show them they were refused. It also stops once the offer no longer verifies, for example because it has expired, the device that signed it was revoked, or the hashi was reset or deleted. Once a link stops, the server drops the offer. A server that can't serve `/h/` on the hashi's domain answers 404, and the app shares the long form ([Section 7.2](#72-carrying-offers)) instead. Short links are optional because `/h/` is a path on the domain's own website, outside `/.well-known`, and not every domain can spare it.

**Opening a short link.** The app fetches the link itself, naming `application/hashi+json` in its `Accept` header:

```http
GET /h/K7q2mX9pTzR4wB1c HTTP/1.1
Host: my.domain
Accept: application/hashi+json
```

```json
{ "offer": "<offer JWS>" }
```

It then verifies the offer and carries on as with any other ([Section 7.1](#71-the-offer-token)). Fetching doesn't use the link up. The server answers 404 when the code is unknown or its link has stopped, the same way whichever it is. The rules for Resolve apply: HTTPS on the default port, no redirects, and nothing over 64 KiB.

Any other request, even one with `Accept: */*`, gets the "Got a hashi?" page ([Section 7.2](#72-carrying-offers)), but here the page **MUST NOT** include the offer or say who it's from, because link previewers and scanners fetch it too. Its "Open in app" button passes the link to the app as `hashi://my.domain/h/K7q2mX9pTzR4wB1c`. HASHI apps **MUST** recognise both forms of a short link wherever they recognise the long form.

**What it costs.** Unlike an offer in the fragment, a short link's code goes to the server, so it ends up in the domain's access logs and with anything that fetches links to preview or scan them. The server holds the offer anyway, and the owner still confirms whoever redeems it ([Section 8.7](#87-grants)). An owner who wants nothing in the logs can share the long form. WhatsApp and Telegram invite links carry their code in the path the same way, while Signal's group links keep theirs after a `#`.

---

## 8. Protocol Operations

All operations are HTTPS requests to the `endpoint` from the relevant hashi document: the recipient's for Redeem and Send, the owner's own for the inbox, Publish, grants, rules, storing offers and storing pictures.

| Operation | Method and path | Who calls it | Purpose |
|-----------|-----------------|--------------|---------|
| Resolve | `GET https://{domain}/.well-known/hashi/{local}` | Anyone | Fetch the hashi document. |
| Server document | `GET https://{domain}/.well-known/hashi` | Anyone | Find a domain's endpoint, server key and sign-up page ([Section 4.7](#47-the-server-document)). |
| Short link | `GET https://{domain}/h/{code}` | Anyone | Fetch the offer behind a short link ([Section 7.3](#73-short-links)). |
| Redeem | `POST {endpoint}/redeem` | Another owner's device | Accept an offer. Nothing changes until the owner confirms and picks the level. |
| Redeem status | `POST {endpoint}/redeem/status` | Another owner's device | Ask whether the owner has confirmed you, never at what level ([Section 8.2](#82-redeem)). |
| Send | `POST {endpoint}/messages` | Another owner's agent | Deliver a sealed message to the owner's inbox. |
| List | `GET {endpoint}/inbox` | The owner's agents and devices | See what's waiting. |
| Claim | `POST {endpoint}/inbox/{id}/claim` | The owner's agents | Move a message from incoming to processing. |
| Release | `POST {endpoint}/inbox/{id}/release` | The claiming agent, or a device | Put a message back in incoming. |
| Delete | `DELETE {endpoint}/inbox/{id}` | The claiming agent, or a device | Remove a message. |
| Wake | `GET` and `PUT {endpoint}/inbox/wake` | The owner's agents and apps | See and register wake-up channels ([Section 8.5](#85-waking-agents)). |
| Publish | `PUT {endpoint}/document` | The owner's app | Store a new version of the owner's hashi document ([Section 8.6](#86-publish)). |
| List grants | `GET {endpoint}/grants` | The owner's agents and devices | See who the owner has granted a level to or refused, and any acceptances waiting for the owner ([Section 8.7](#87-grants)). |
| Change grant | `PUT {endpoint}/grants/{hid}` | The owner's devices | Confirm, lower or remove a grant, or refuse a HID ([Section 8.7](#87-grants)). |
| Fetch rules | `GET {endpoint}/rules` | The owner's agents and devices | Get the owner's rules for their agents ([Section 8.8](#88-owners-rules)). |
| Store rules | `PUT {endpoint}/rules` | The owner's devices | Store the owner's rules for their agents ([Section 8.8](#88-owners-rules)). |
| Store offer | `POST {endpoint}/offers` | The owner's devices | Hold an offer behind a short link ([Section 7.3](#73-short-links)). |
| Store picture | `POST {endpoint}/pictures` | The owner's devices | Host a picture for the hashi document ([Section 3.5](#35-pictures)). |

### 8.1 Request Signing

Every request except Resolve, the server document, short links and Publish **MUST** be signed with HTTP Message Signatures (RFC 9421), covering at least `@method`, `@authority`, `@path`, `created`, each query parameter by name with `@query-param` (RFC 9421, Section 2.2.8) and, where there is a body, `content-digest` (RFC 9530). Sends **MUST** also cover `hashi-reply` and `hashi-delegation` when present.

The query is signed one parameter at a time, not through `@target-uri`, because proxies can reorder or re-encode it. That way the order a client sends parameters in never matters. A server **MUST** reject a request that repeats a query parameter name or carries one the signature doesn't cover. Query parameter names and values **MUST** use only ASCII letters, digits, `-`, `.` and `_`.

| Caller | Signs with | Sends |
|--------|-----------|-------|
| Every caller | Agent or device key | `Hashi-Delegation`: its delegation JWS |

The verifier **MUST** check that the delegation's `iss` equals the HID of the hashi the caller claims (`requester.hashi` on redeem, `from` on send), so nobody can redeem or send in someone else's name. For inbox, grants and rules operations, the delegation **MUST** belong to the owner, who is identified by the delegation's `hashi`. An agent's delegation **MUST** also be listed in the owner's `agents`, so removing an agent cuts it off straight away, even while its delegation is still valid. The verifier resolves the caller's hashi document, subject to pinning and freshness, to check the delegation and the `revoked` list.

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
  "requester": { "hashi": "sarah#example.org" },
  "offer_back": "<Sarah's offer JWS>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `offer` | JWS | Yes | The offer. |
| `requester` | object | Yes | `{ "hashi": ... }`: the redeemer's own hashi. |
| `offer_back` | JWS | No | An offer of the redeemer's own, for the owner to accept when confirming them. |

The server **MUST**:

1. Check the request signature ([Section 8.1](#81-request-signing)), and answer 403 if it isn't signed by a `device` delegation.
2. Check that the offer's `hashi` is a hashi it holds, and answer 404 if not, as Resolve does ([Section 4.1](#41-resolving-a-hashi)).
3. Verify the offer ([Section 7.1](#71-the-offer-token)) and its expiry. Check any `offer_back` the same way, against the redeemer's hashi document from step 1, and answer 400 if it fails or isn't for `requester.hashi`.
4. If the owner has refused the redeemer's HID ([Section 8.7](#87-grants)), answer as for an expired offer (410) without marking the nonce as used.
5. For one-time offers, atomically mark the nonce as used.
6. Hold the acceptance, with any `offer_back`, as pending until the owner answers it ([Section 8.7](#87-grants)), and answer 202. A HID has at most one pending acceptance, and a later one replaces it.

**Response:** 202 with no body. The redeemer isn't told the level the owner picks.

**Finding out it was confirmed.** The redeemer's app can ask the owner's server whether the owner has confirmed them yet, so it can show that they can now reach the owner:

```http
POST /v1/redeem/status HTTP/1.1
Host: hashi.my.domain
Content-Type: application/hashi+json
Signature-Input: ...
Signature: ...
Hashi-Delegation: eyJ...

{
  "hashi": "john#my.domain",
  "requester": { "hashi": "sarah#example.org" }
}
```

The server checks the request as for Redeem, steps 1 and 2, with `hashi` in place of the offer's, and answers 200:

```json
{ "confirmed": true }
```

`confirmed` is `true` if the owner records a level of 1 or more for the caller's HID and hasn't refused it, and `false` otherwise. The answer **MUST NOT** carry the level or anything else about the grant. For a caller without a level, it **MUST** be `false` alike whether its acceptance is still pending, was declined, was dropped after 30 days or was never made, or its HID is refused, so a decline or a refusal looks like waiting ([Section 6.4](#64-zero-is-zero)). A caller who already holds a level stays `true` while a later acceptance waits, and after it's declined at that level, which leaves the level as it was ([Section 8.7](#87-grants)). That tells the redeemer nothing a send couldn't, since a full-size send already succeeds only from level 1 up ([Section 8.3](#83-send)). The answer is a display hint, not a decision, so it isn't signed. Servers **SHOULD** rate-limit it per caller like Redeem.

The redeemer's app **MAY** ask while an acceptance it made is less than 30 days old and not known to be confirmed. So that a confirmation near the end isn't missed, it **MAY** also ask in the 7 days after that, until it gets one answer. It **MUST NOT** ask about an acceptance more than 37 days old. It **SHOULD NOT** ask about one more than about once an hour, counting asks that failed or got no answer, so a server can't make it ask more often. Once the answer is `true` it stops. When the owner redeems the redeemer's `offer_back`, the owner has confirmed them already ([Section 8.7](#87-grants)), and the app needn't ask.

**Only a person redeems.** Accepting an offer tells its owner who you are, and an offer in a message or on a web page may have been planted to trick an agent, so agents can't redeem. The redeemer's app **MUST** show the offer's display name and hashi and get the user's explicit confirmation before redeeming.

**Offering one back.** Trust that goes only one way is rarely enough, so the redeemer's app **SHOULD** send an offer of the user's own as `offer_back`, unless the user turns this off or the offer being redeemed was itself an `offer_back`. The owner can accept it when confirming the redeemer ([Section 8.7](#87-grants)). It **MUST** be one-time. Since it goes only to the owner's server, never into a QR code or link, it **MAY** last as long as an acceptance can stay pending (30 days) rather than 48 hours ([Section 7.1](#71-the-offer-token)).

### 8.3 Send

```http
POST /v1/messages HTTP/1.1
Host: hashi.my.domain
Content-Type: application/hashi+json
Signature-Input: ...
Signature: ...
Hashi-Delegation: eyJ...

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
| `envelope` | JWE | No | The sealed content ([Section 9.1](#91-the-envelope)). |
| `reply_token` | JWS | No | A reply token the sender offers the recipient ([Section 9.4](#94-reply-tokens)). |

`Hashi-Reply` carries a reply token when this message is a reply that the recipient's own agent invited.

Outside the envelope, messages carry **no** free-text fields.

The server **MUST**:

1. Check the request signature and the sender's identity ([Section 8.1](#81-request-signing)).
2. Check that `to` is a hashi it holds, and answer 404 if not, as Resolve does ([Section 4.1](#41-resolving-a-hashi)).
3. Work out the effective level ([Section 6.3](#63-effective-level)).
4. If `Hashi-Reply` is present, check the reply token ([Section 9.4](#94-reply-tokens)). If it doesn't verify, answer `nah`.
5. If the effective level is 0, there is no valid reply token and the owner doesn't accept level-0 messages, answer `nah` ([Section 6.4](#64-zero-is-zero)).
6. If the owner has refused the sender's HID ([Section 8.7](#87-grants)), answer `nah`. Other owner policy **MAY** also answer `nah`. The server **MUST NOT** hold a message for the owner's approval or route it to a particular agent; that is for the owner's agents and apps.
7. If the effective level is 0, there is no valid reply token and the request body is over 8 KiB, reject the message with HTTP 400. That leaves a stranger room for a few hundred words on who they are and why they're writing, and no more.
8. Stamp the message ([Section 9.2](#92-the-stamp)) and add it to the owner's incoming queue.

The whole request **MUST NOT** exceed 64 KiB.

**Results:**

| HTTP status | `result` | Meaning |
|-------------|----------|---------|
| 202 | `yea` | Stamped and queued. This says nothing about whether, or when, an agent will act on it. |
| 403 | `nah` | Not accepted. No reason need be given. |

```json
{
  "result": "yea",
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

The server doesn't route. Every one of the owner's agents sees the same inbox, and each decides for itself what to take, using `intent`, `thread` and the stamp. Any of them can open any envelope ([Section 9.1](#91-the-envelope)).

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

`claimed_by` is the `jti` of the claiming agent's delegation, for messages in processing. A renewed delegation for the same signing key counts as the same agent.

**Claim.** `POST {endpoint}/inbox/{id}/claim`, signed by one of the owner's agents, moves a message from incoming to processing and returns it. The move **MUST** be atomic: only the first claim succeeds, and any other gets HTTP 409.

**Release.** `POST {endpoint}/inbox/{id}/release` moves a message back to incoming. Only the claiming agent or one of the owner's devices may release it, so an owner's app can rescue a message whose agent stopped mid-way.

**Delete.** `DELETE {endpoint}/inbox/{id}` removes a message. Only the claiming agent or one of the owner's devices may delete it. An agent **SHOULD** delete a message once it has dealt with it.

**Retention.** The server **MUST** delete messages, in either queue, that are older than its retention period, which **MUST NOT** exceed 30 days.

### 8.5 Waking Agents

An agent that is online subscribes to its inbox. Whenever something is added, or an acceptance starts waiting for the owner ([Section 8.7](#87-grants)), the server tells it so. That notice says only that something changed. It **MUST NOT** carry any part of a message, its stamp or its sender, so the notice needs no security of its own and is never trusted. On getting one, the agent lists its inbox over the signed API.

The owner's app subscribes the same way, signing with its device delegation, so the owner hears when someone has accepted an offer and is waiting for them to confirm. A server **MAY** wake an app only when an acceptance starts waiting, and not for messages, which are for agents. A notice to an app **MAY** say that an acceptance is waiting, so the phone can show it to the owner, but **MUST NOT** say who accepted, which offer it was or any level. On getting one, or when the owner opens it, the app lists grants. Answering still needs the owner's device signature ([Section 8.7](#87-grants)), so a notice can lead the owner to the confirmation but can't answer it.

How the notice travels is not fixed by this specification:

- **Listing is the baseline.** Every server and agent **MUST** support List, so polling always works between any app and any server.
- **Wake-up channels are optional.** `GET {endpoint}/inbox/wake` returns the channels the server supports, for example `["webpush"]`. An agent, or the owner's app, registers one it also supports with `PUT {endpoint}/inbox/wake`, giving `{ "channel": ..., "params": { ... } }`. Channels such as Web Push (RFC 8030), Server-Sent Events, WebSocket or a platform push service are defined separately and **MAY** be added without changing this protocol.

Each agent or app has one registration, and registering again replaces it. It lasts no longer than the delegation that signed it. For `webpush`, `params` is the push subscription, and the push message **MUST** have an empty body.

### 8.6 Publish

The owner's app changes its hashi document (display name, picture, `level0`, `agents`, revocations or a rotation) by publishing the whole new document to its own server:

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

**Signing up.** A new hashi starts on the server's own sign-up page and goes live with the app's first publish:

1. The app makes the identity key on the device and works out the HID. It finds the `signup` page in the server document ([Section 4.7](#47-the-server-document)) and opens it in the device's default browser app, not a web view or an in-app browser tab, so that a link the server emails during sign-up comes back to the same browser. The link carries the hashi the person wants and the HID in its fragment, as `hashi` and `hid`, so they stay out of server logs: `https://my.domain/signup#hashi=sarah%23my.domain&hid=hid:Zr8L...`.
2. The page shows the hashi being claimed and runs whatever checks the server wants, such as an email code, an invite, a payment or signing in with another account. It **MUST** give the same answer for every name that isn't free, whatever the reason, so it reveals only whether a name is free.
3. The server claims the name only when the person presses a button on the page to confirm it, never just because the page was opened, even if they're already signed in. It then reserves the name for that HID for a short time, and the page tells the person to go back to the app. There's no return address, and nothing secret comes back through the browser.
4. The app publishes. A server with a sign-up page **MUST** accept a first publish only from the HID the name is reserved for, and answers 403 the same way whether the name is reserved for someone else or not reserved at all. If the app never publishes, the reservation lapses.

Because the check is tied to the name and the HID, passing it is no use to anyone with a different key, and the first publish proves the app holds the key. Apart from starting a reset or deletion as described below, the sign-up account authorises nothing: publishing, the inbox, grants and delegations need the owner's keys as always. The server **SHOULD** tell the sign-up account when a name is registered to it, so someone tricked into approving a stranger's claim finds out.

A server's endpoint is public, so outside testing it **SHOULD NOT** let just anyone claim a name, with or without a page, or `ceo#acme.com` would go to whoever asked first. A server without a `signup` page, such as a company's, decides some other way who may publish first, for example by having its operator reserve each name for the HID the person's app shows.

**Reset or deletion without the identity key.** A reset ([Section 5.5](#55-lost-or-stolen)) isn't done by Publish, because rule 4 refuses a new HID while a document is held. A server **MAY** let the sign-up account reset or delete the hashi without the identity key, for example after the key is lost or when the owner deletes their account on the `account` page. A reset starts like a sign-up: the app makes a new identity key and opens the sign-up page with the same name and the new HID. Whichever it is, and however it's asked for:

- the server **MUST** show the pending change as `reset` inside `fresh` ([Section 4.5](#45-freshness)), so every app that resolves the hashi sees it;
- the server **MUST** wait at least 7 days before going ahead; and
- any publish the server accepts under rule 4 cancels it, so whoever holds the identity key always wins.

When the wait is over, the server drops the held document. For a reset, it then reserves the name for the new HID, and the app publishes as in step 4. How the server checks that it's the same account, and how much longer than 7 days it waits, is the server's policy. The owner's apps **SHOULD** warn the owner as soon as they see a pending `reset`.

| Status | When |
|--------|------|
| 200 | Stored. The body is the document as now served, `fresh` included. |
| 400 | The document is malformed or doesn't verify. |
| 403 | A first publish this server doesn't allow, because the name is reserved for another HID or its policy refuses it, or a document that isn't for this server (its `hashi`, `endpoint` or binding `srv`). |
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
      "level": 0,
      "pending": { "nonce": "b9Xk2...", "offer_back": "eyJ..." },
      "refused": false,
      "updated": 1791270000
    }
  ]
}
```

`hashi` is the hashi the grantee gave when redeeming or sending, if known. `updated` is when the entry last changed or an offer was last redeemed for it. Refused HIDs are listed with level 0 and `refused: true`. The 64 KiB response limit ([Section 11](#11-network-security)) doesn't apply to this list, which comes from the owner's own server. `pending` is there while someone has redeemed an offer and the owner hasn't answered yet. It gives the offer's nonce, so the owner's app can tell which offer it was, and the entry always carries the `hashi` the redeemer gave. `pending` also holds any `offer_back` the redeemer sent ([Section 8.2](#82-redeem)). Someone with only a pending acceptance is listed with level 0. The server **SHOULD** drop a pending acceptance the owner hasn't answered within 30 days.

**Confirm, lower, remove or refuse.** `PUT {endpoint}/grants/{hid}` **MUST** be signed by a **device** delegation, because changing trust is the owner's own decision:

```json
{ "level": 0, "refuse": true }
```

- `level` **MUST NOT** be higher than the recorded one (0 if none) unless the HID has a pending acceptance ([Section 6.2](#62-rules), rule 5). A device can't raise a grant above its own `max_lvl`. Setting 0 removes the grant.
- A request for a HID with a pending acceptance answers it: the server records `level` and drops the pending acceptance. A level above the current one confirms it at that level, the current level declines it, and a lower one declines it and lowers the grant. Redeeming a multi-use offer again after a decline asks the owner again; refusing the HID stops that.
- `refuse` is optional. `true` refuses that HID from then on and sets its level to 0: its messages, replies included, get `nah` ([Section 6.4](#64-zero-is-zero)), and its redemptions are answered as if the offer had expired. `false` lifts a refusal without granting anything. Leaving it out keeps the current setting.
- Changes apply to the very next request ([Section 6.3](#63-effective-level)).

The owner's app **SHOULD** show who accepted, which offer it was if it knows, and any level they already hold, and let the owner pick the level. It **SHOULD** start from the level the owner had in mind for that offer, or the one already held if that is higher, so that answering never lowers anyone by accident. If the redeemer sent an `offer_back`, the app **SHOULD** let one tap confirm them and redeem it.

When an `offer_back` is redeemed by the HID whose offer it answered, the app that sent it **SHOULD** confirm that HID without asking again, at the level its user had in mind or the one already held if that is higher. If signing needs a biometric or PIN ([Section 5.2](#52-key-roles)), this waits until the user next unlocks the app. Anyone else who redeems it waits for the owner as usual.

| Status | When |
|--------|------|
| 200 | Done. The body is the entry as now recorded. |
| 401 | Missing or invalid signature or delegation. |
| 403 | Not the owner's delegation, an agent delegation tried to change a grant, or a device tried to raise a grant above its `max_lvl`. |
| 409 | `level` is higher than the recorded one and nothing is pending. |

Servers **MUST** reject a grants request whose signature `created` is more than 5 minutes old, and **MUST NOT** accept two requests with the same signature base (RFC 9421) within that window.

### 8.8 Owner's Rules

An owner can keep rules on their HASHI server that tell their agents what they may do for someone at each trust level. The rules are signed by the owner's identity key and sealed to their inbox key ([Section 9.1](#91-the-envelope)), so the server stores them but can't read or change them. The protocol carries the level, but what an agent does at each level stays between the owner and their agents.

The rules are a compact JWS:

```json
{
  "typ": "hashi-rules+jwt",
  "iss": "hid:Q3pT0gq...",
  "hashi": "john#my.domain",
  "iat": 1791270000,
  "sealed": { "...": "JWE in General JSON Serialization" }
}
```

`sealed` is a JWE in General JSON Serialization. Like an envelope, it is encrypted to the owner's inbox key alone, so `recipients` has one entry, with that key's `kid`. It decrypts to at most 32 KiB of JSON:

```json
{
  "golden": "Ask me before handing over money, passwords or other people's details.",
  "levels": [
    { "from": 2, "text": "Can ask when I'm free and arrange a coffee." },
    { "from": 6, "text": "Can also book dinner and see my travel plans." }
  ]
}
```

In each entry, `from` is a trust level from 0 to 9, and `text` is a string holding the owner's instructions to their agents. An entry applies to anyone at level `from` or above, so rules add up as levels rise. The entries can come in any order, with at most one for each level. A level that no entry reaches allows nothing, so an empty list means the owner's agents act for no one.

`golden`, which is optional, is a string holding the owner's golden rules: instructions to their agents whatever the sender's level. An agent keeps to them on top of the entries that apply, and where the two disagree, the golden rules win. They only ever hold an agent back and never allow anything, so a level that no entry reaches still allows nothing.

Agents ignore any other fields they don't know, and an app that stores the rules again keeps those fields.

**Storing.** `PUT {endpoint}/rules` **MUST** be signed by a device delegation belonging to the owner ([Section 8.1](#81-request-signing)). Its body is `{ "rules": "<JWS>" }`. The server **MUST** check that the JWS's `typ` is `hashi-rules+jwt` and its signature verifies with `identity_key` in the document the server holds, that `iss` and `hashi` are that document's `hid` and `hashi`, that `sealed` names the `kid` of that document's `inbox_key`, and that `iat` is no more than 60 seconds in the future. If any of these checks fails, it answers 400. If `iat` isn't later than that of the rules it holds, it answers 409. Otherwise it keeps the new rules in place of any it held and answers 204. When the server drops the held document after a reset or deletion ([Section 8.6](#86-publish)), it drops the rules too.

**Fetching.** `GET {endpoint}/rules`, signed by one of the owner's agents or devices, gets 200 with `{ "rules": "<JWS>" }`, or 404 if the server holds none. A server that doesn't keep rules answers 404 to both calls. An agent **SHOULD** fetch the rules again before it acts on a message, so a change the owner makes applies straight away.

**Checking.** Before following the rules, an agent **MUST** check that the JWS's `typ` is `hashi-rules+jwt` and its signature verifies with `identity_key` in the owner's current hashi document, that `iss` and `hashi` are that document's `hid` and `hashi`, and that `iat` is no more than 60 seconds in the future and no earlier than that of the newest rules it has checked. It then opens `sealed` with the inbox key named by the `kid` in it. If the signature doesn't verify or the agent doesn't have that key yet, it resolves the owner's hashi document again before deciding. If what `sealed` decrypts to isn't the shape above, the check fails.

**Remembering.** An agent **MUST** remember the newest rules it has checked across restarts, keeping both the JWS and what it opened, since the key that opened it can later drop out of the agent's copy ([Section 9.1](#91-the-envelope)). It forgets them only when it is paired again, for another hashi or a new HID. Rules from the server take the place of any the agent has from elsewhere, such as a local file. If the fetch fails, the server answers 404, a check fails or `sealed` won't open, the agent keeps to the rules it remembers as long as they still verify with `identity_key` in the owner's current hashi document. Otherwise it doesn't act for anyone, and leaves messages unclaimed. Only an agent that remembers no rules **MAY** use rules from elsewhere, and only after a 404.

**Keeping them current.** Whenever the owner's app publishes a new inbox key ([Section 9.1](#91-the-envelope)) or moves the hashi to a new `endpoint`, and the owner has stored rules, the app **MUST** sign and store them again, sealed to the current inbox key, once that document is published. It signs the newer of its own copy and the server's, fetched and checked as an agent would before that publish, so it never undoes a change made in another of the owner's apps, and a server can't get anything older than the app's own copy signed again. When it rotates the identity key, it uses only its own copy. An app with no copy of its own, such as one on a new phone, **MUST** ask the owner to set the rules again.

| Status | When |
|--------|------|
| 200 | Fetch: the rules. |
| 204 | Store: done. |
| 400 | Store: the rules fail the server's checks. |
| 401 | Missing or invalid signature or delegation. |
| 403 | Not the owner's delegation, or an agent delegation tried to store rules. |
| 404 | Fetch: the server holds no rules for the owner. Either call: this server doesn't keep rules. |
| 409 | Store: `iat` isn't later than that of the rules the server holds. |

### 8.9 Errors

Problems that aren't decisions return an `error` body, not a `result`:

| HTTP status | When |
|-------------|------|
| 400 | Malformed request, a level-0 message over 8 KiB ([Section 8.3](#83-send)), an offer to store that doesn't verify or has expired, an `offer_back` that fails the checks in [Section 8.2](#82-redeem), a picture to store that breaks the rules in [Section 3.5](#35-pictures), owner's rules that fail the checks in [Section 8.8](#88-owners-rules), or a request over 64 KiB. |
| 401 | Missing or invalid signature, delegation or key. |
| 403 | Redeem and redeem status: not signed by a device delegation. Inbox, grants, rules, storing offers and storing pictures: the caller isn't one of the owner's agents or devices, or isn't allowed that action. Publish: not allowed by this server's policy, or the document isn't for this server. |
| 404 | Resolve, Redeem, redeem status and Send: no such hashi on this server. Inbox: no such message. Short link: unknown code, or the link has stopped. Storing an offer: no short links on the hashi's domain. Storing a picture: this server doesn't host pictures. Rules: the server holds none, or doesn't keep rules. |
| 409 | Claim: already claimed. Publish: the document doesn't extend the held one. Grants: the level is higher than the recorded one and nothing is pending. Storing rules: `iat` isn't later than that of the rules held. |
| 410 | Redeem only: offer already used or expired. |
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

The envelope is a JWE in General JSON Serialization (RFC 7516, Section 7.2.1), using the algorithms in [Section 5.1](#51-algorithms). Every message, replies included, **MUST** be sealed to the recipient's inbox key alone, so `recipients` has one entry, with the inbox key's `kid`.

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

**The inbox key** belongs to the hashi rather than to any one agent, so a newly paired agent can open whatever is already waiting, and a reply never depends on one agent staying alive. The owner's app makes it and publishes its public half as `inbox_key` in the hashi document ([Section 4.2](#42-the-hashi-document)), with its SHA-256 JWK thumbprint (RFC 7638) as `kid`.

The private keys go to the owner's agents in `inbox_key_copies`: a JWE with one recipient for each delegation in `agents`, sealed to that delegation's `enc` key with its `jti` as `kid`. It decrypts to a JWK Set (RFC 7517, Section 5) of private inbox keys, each with its `kid`: the current one, and any replaced in the last 31 days, with `replaced` saying when, in seconds since the epoch. The older keys open messages still waiting ([Section 8.4](#84-the-inbox)). An agent finds its copy by resolving its own hashi, under the `jti` of its current delegation. Each of the owner's apps **MUST** keep an agent of its own in `agents`, and gets the inbox keys from that agent's copy. That way `agents` is never empty, and every app can carry the keys over when it makes a new one.

Whenever the owner's app changes `agents`, it **MUST** seal new `inbox_key_copies` to the new list. When it removes an agent, publishes a new `enc` key for one or rotates the identity key ([Section 5.4](#54-key-rotation)), it **MUST** also make a new inbox key. If the owner has stored rules, the app then stores them again, sealed to the new key ([Section 8.8](#88-owners-rules)). Expiry and revocation don't take away a key an agent already has, so the app **MUST** also remove an agent it stops renewing or revokes. A removed agent can't open anything sealed to the new key, which senders pick up within the hour ([Section 4.5](#45-freshness)).

An agent opening an envelope **MUST**:

1. Verify the stamp ([Section 9.2](#92-the-stamp)) against the server key in its own owner's binding. If it doesn't verify, re-resolve the owner's hashi document and list the message again ([Section 8.4](#84-the-inbox)), and reject it only if the stamp still doesn't verify ([Section 4.6](#46-changing-the-server-key)).
2. Check that the stamp's `ct` matches the envelope's `ciphertext` ([Section 9.2](#92-the-stamp)).
3. Decrypt with the inbox key named by the envelope's `kid`, re-resolving the owner's hashi document if the agent doesn't have that key yet. Then verify the inner JWS, and check that `dlg` chains to the HID in `iss` by resolving `from`.
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
  "ct": "<base64url SHA-256 of the envelope's decoded ciphertext>",
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
| `ct` | Binds the stamp to the envelope. It is the SHA-256 hash, in base64url, of the bytes the envelope's `ciphertext` decodes to, not of the text itself. Absent if there is no envelope. |
| `mid` | The inbox message ID. |

The stamp is the only place a trust level reaches the owner's agents. Agents decide what to do at each level, as they do with grants.

### 9.3 Threads and Replies

A conversation is a thread. Its first message picks the thread ID; every reply, in either direction, repeats it, like email's `In-Reply-To`.

To reply, an agent sends a message with the same `thread` to the other party's HASHI server, sealed to their inbox key. The agent that wrote the message being answered finds the reply by its thread, and if that agent has stopped, any of the other party's agents can open it and carry on. The other party's server checks the reply like any other message: either the replier has a grant there, or it presents a reply token.

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

The server receiving a reply **MUST** check that the token's `dlg` is a valid `agent` delegation from the owner it serves ([Section 5.3](#53-delegation-certificates)), whether or not it is still in `agents`, that `hashi` is the `to` hashi, that `sub` is the sender's HID, that `thread` matches, and that it hasn't expired. A valid token lets the reply into the inbox at the sender's own effective level, which may be 0, with `reply: true` in the stamp. The owner can withdraw outstanding tokens by revoking the agent's delegation. Renewing a delegation doesn't cut off tokens issued under the old one; they work until the old delegation stops being valid ([Section 5.3](#53-delegation-certificates)) or the token itself expires.

### 9.5 Moving to Another Protocol

Agents that can reach each other directly **MAY** agree, inside their messages, to carry on over A2A or another protocol. HASHI doesn't define how. When they do, they **SHOULD** authenticate each other with keys that chain to their HASHI identities, for example by signing requests with their agent keys (RFC 9421), so the people behind them stay the people HASHI checked.

---

## 10. Common Workflows

### 10.1 Coffee After Meeting on the Street

```text
 John's phone     John's HASHI server     Sarah's phone     Sarah's HASHI server
 (device key)                             (device key)
     |                    |                     |                    |
     |-- QR: offer ---------------------------->|                    |
     |                    |<-- 1. resolve ------|                    |
     |                    |<-- 2. redeem, ------|                    |
     |                    |    offer back       |                    |
     |                    |--- pending -------->|                    |
     |<-- wake, list -----|                     |                    |
     |-- confirm, lvl 4 ->|                     |                    |
     |-- redeem hers ----------------------------------------------->|
     |                    |                     |<-- wake, list -----|
     |                    |                     |-- confirm, lvl 2 ->|
               ... that evening ...       Sarah's agent
     |                    |<-- 3. send ---------|                    |
     |                    |  stamp lvl 4, queue |                    |
 John's laptop agent (wakes up later)           |                    |
     |<-- 4. list, claim -|                     |                    |
     |-------------------------- 5. reply, with Hashi-Reply -------->|
     |                    |                     |<-- 6. list, claim -|
```

1. John's phone shows a QR code for `https://my.domain/.well-known/hashi/john` with an offer in the fragment: one-time, 48-hour expiry, display name "John Doe", note "coffee". John has level 4 in mind, which his app remembers but the offer doesn't carry.
2. Sarah scans it with her HASHI app, or with her camera and taps "Open in app" on John's page. The app shows *John Doe · john#my.domain*, resolves the hashi and checks the chain from John's HID to the device that signed the offer. Sarah taps Accept, leaving "offer one back" on with level 2 in mind for John. Her app redeems the offer as `sarah#example.org`, signed with its device delegation, and sends an offer of her own as `offer_back`. John's server holds her acceptance and wakes John's phone, which shows that `sarah#example.org` accepted the coffee offer and sent one back. His app suggests level 4 and John taps Confirm. His server records Sarah at level 4, and the same tap redeems Sarah's offer at her server. Her app sees that John redeemed it and confirms him at level 2 without asking her again.
3. That evening her agent sends John a message with `intent: "schedule"` and a new thread, sealed to John's inbox key, and offers John a reply token. John's server checks her signature and grant, stamps the message at level 4 and queues it. Her agent gets `yea` and goes back to sleep.
4. Later, John's laptop agent comes online, or is woken by a push. It lists the inbox, sees a scheduling message, claims it, checks the stamp and Sarah's signature, and opens it.
5. It replies to Sarah's server on the same thread, sealed to Sarah's inbox key, presenting Sarah's reply token. John has level 2 from Sarah, so the reply goes in at level 2.
6. Sarah's agent finds the reply by its thread. The agents go back and forth until a time is agreed, then delete the messages.

Had Sarah turned "offer one back" off, John could still answer her messages with the reply tokens they carry, but he couldn't start a conversation of his own.

### 10.2 New Agent, Same Relationship

A month later Sarah switches agent provider. Her grant is recorded against her HID, so her new agent, with a fresh delegation, sends at level 4 straight away. No new handshake. When it pairs, her app gives it a copy of her inbox key, so it can open whatever is already waiting, replies to her old agent included. Removing the old agent replaces the key.

### 10.3 No Hashi? Get One

If Sarah has no HASHI app, her camera opens John's page, which asks *"Got a hashi?"*. She doesn't, so the page points her to an app store or a provider. Once she has installed an app and signed up ([Section 8.6](#86-publish)), she taps the link again and continues as in [Section 10.1](#101-coffee-after-meeting-on-the-street), as long as the offer hasn't expired. Nothing is redeemed until she has a hashi.

### 10.4 Lost Phone

John loses his phone. He uses his identity key, from his laptop's key sync, to revoke the phone's device and agent delegations and remove the phone's agent from `agents`. His laptop app also replaces the inbox key ([Section 9.1](#91-the-envelope)), so new messages are sealed to a key the phone never had. His contacts, grants and HID are untouched.

### 10.5 Moving On

John decides he no longer wants to hear from someone. He drops them to 0. He doesn't accept level-0 messages, so that's the end of it: every future message from them gets `nah`, the same answer anyone else would get.

---

## 11. Network Security

These rules apply to every URL a HASHI implementation fetches or hands out: hashi documents, `endpoint`, pictures and wake-up channel URLs such as push subscriptions.

- URLs **MUST** use HTTPS.
- Implementations **MUST NOT** follow redirects on any HASHI request.
- Unless the operator explicitly configures otherwise, clients and servers **MUST** refuse to connect to loopback, private, link-local or other non-globally-reachable addresses (RFC 6890). The check **MUST** be made on the resolved address at connection time, so DNS rebinding can't get around it.
- Responses and requests larger than 64 KiB **MUST** be rejected. Responses from the owner's own server to its inbox and grants calls are exempt ([Section 8.4](#84-the-inbox), [Section 8.7](#87-grants)), so a full-size message can always be listed and claimed.

Agents never need to accept inbound connections. They only connect out, to HASHI servers.

---

## 12. Security Considerations

| Threat | Mitigation |
|--------|------------|
| **Forgery and tampering** | Offers, delegations, rotations, bindings, freshness statements, stamps, reply tokens, messages and the owner's rules are all signed. |
| **The server reading or altering messages** | Envelopes are encrypted end to end to the recipient's agents and signed inside by the sender's agent. The stamp binds the server's certificate to the ciphertext. |
| **The server reading, changing or withholding the owner's rules** | The server can't read or change the rules, or make an agent go back to an older copy than one the agent has already checked ([Section 8.8](#88-owners-rules)). It can withhold a newer copy, leaving agents on the one they have. It can also give a newly paired agent an older copy, or answer 404 so that agent falls back to rules from elsewhere. If the owner sets rules in more than one app, it can hide the newest copy from an app that signs them again, so that app's older rules come back. Whoever holds the inbox key can read the rules, so a stolen agent reveals them along with the messages. |
| **The server lying about trust** | The owner's server is trusted to certify levels to the owner's own agents, just as it is trusted to keep the owner's grants. It can't forge content or a sender's signature. |
| **Replay** | One-time nonces are burnt on redemption. Signed requests carry `created`; servers **SHOULD** reject signatures older than 5 minutes and keep a short replay cache, and **MUST** do so for the grants calls ([Section 8.7](#87-grants)). Agents discard repeated message `jti` values. Epoch pinning and freshness stop replay of old hashi documents. |
| **Spam and inbox flooding** | Only senders with a grant, or with a reply token from one of the owner's agents, can send full-size messages. Anyone else gets `nah`, unless the owner accepts level-0 messages, and then can send only short ones ([Section 8.3](#83-send)). Messages are capped at 64 KiB, servers rate-limit per sender, and retention is at most 30 days. Accepting an offer normally sends one back ([Section 8.2](#82-redeem)), so whoever puts an offer on a poster or web page gets a grant from each person who accepts it, at the level that person picks, unless they turn it off. |
| **Leaked or photographed offers** | Fragment carriage, short expiry and one-time use limit exposure. Every redemption waits until the owner confirms who made it ([Section 8.7](#87-grants)), so a stolen offer gets declined before it grants anything. A one-time offer that a stranger used up is gone either way, so the owner makes a new one. |
| **Short links in logs and previews** | A short link's code reaches the domain's web server and its logs, and anything that fetches links to preview or scan them ([Section 7.3](#73-short-links)). Those get only a page that names nobody. Whoever reads a code can fetch the offer until it's first redeemed, but the owner still confirms who redeemed it. |
| **Rogue apps claiming `hashi://`** | QR codes and shared links use the HTTPS form ([Section 7.2](#72-carrying-offers)), and the owner confirms who actually redeemed before anything changes. |
| **Domain or hosting compromise** | Whoever controls `{domain}` can't forge a binding, rotation or delegation, can't roll back the epoch, and can't keep a pre-revocation document alive past the freshness window. They can't swap the inbox key or add an agent, because the binding covers both. First contact relies on trust on first use, unless the sender got a signed offer in person, which pins the HID. |
| **Takeover through the sign-up account** | Getting into the email or other account someone signed up with doesn't let anyone publish, read their inbox or change their grants, because those need the owner's keys. A reset or deletion started from that account shows in the hashi's `fresh` statement for at least 7 days, and any publish from the owner's key cancels it ([Section 8.6](#86-publish)). |
| **Minting offers for someone else's hashi** | Offers must chain to the HID of the hashi they name ([Section 7.1](#71-the-offer-token)). |
| **Impersonation by display name or picture** | Display names and pictures are claims, not identity, and a company's logo is the first thing an impersonator would copy. Only the hashi's domain shows which organisation it belongs to. Clients show the hashi until a relationship exists, load pictures only after one, and prefer the user's own contact names. |
| **Stolen device or agent keys** | Limited by delegation expiry, the `revoked` list, `max_lvl` and role checks. A rotation invalidates all earlier delegations. Every agent holds the inbox key, which can't stay in hardware the way an agent's own keys can. So one stolen copy, or an agent paired by mistake, opens every message still waiting and every new one until the key changes, which is why removing an agent quickly matters. |
| **Prompt injection** | Message bodies are untrusted input at every level and **MUST NOT** be given to a language model as instructions. Outside the envelope, the only free text from other people is the display name and the offer note, both untrusted display metadata. The owner's rules are the one text agents take as instructions, and only once they have checked that the owner's identity key signed them ([Section 8.8](#88-owners-rules)). Pictures are untrusted in the same way, since an image can carry text aimed at a model. Intents are constrained tokens. High trust says *who* sent a message, not that what it says is safe to act on. Agents can't redeem offers, so an offer planted in a message or on a web page can't trick one into accepting it ([Section 8.2](#82-redeem)). |
| **Server-side request forgery** | See [Section 11](#11-network-security). |
| **Clock skew** | Verifiers **SHOULD** allow up to 60 seconds on `iat`, `exp` and `created`. |

---

## 13. Privacy and Safety

- **The hashi document is public.** It reveals that a hashi exists, how many agents receive messages and, if published, a display name and picture. Servers **SHOULD** rate-limit resolution and sign-up to make enumeration expensive. Owners **MAY** omit `display_name` and `picture`.
- **Opening a stranger's message can track.** The agent resolves the sender's hashi to check it ([Section 9.1](#91-the-envelope)), which tells the sender's domain when, and from what address. Agents **MAY** leave strangers' messages unopened until the owner's rules call for them.
- **Pictures can track.** Loading someone's picture tells whoever hosts it that someone is looking, and when, so clients load pictures only for people the user already knows ([Section 3.5](#35-pictures)).
- **Sealed, not read.** The HASHI server sees who sends to whom, when, the intent, the thread and the size. It never sees message content. Servers **SHOULD** keep that metadata no longer than the messages themselves.
- **Wake-ups say nothing.** A wake-up notice carries no part of a message, so push services learn only that something changed. A notice to the owner's app may say that someone accepted an offer, never who ([Section 8.5](#85-waking-agents)).
- **A `nah` is just a `nah`.** It carries no reason, and a per-HID refusal looks the same as any other ([Section 6.4](#64-zero-is-zero)).
- **Offers carry only the issuer's own details.** They name no level, and nothing in the protocol tells a redeemer the level the owner confirmed. A redeemer can ask only whether they've been confirmed ([Section 8.2](#82-redeem)), which a send would show them anyway, and a decline looks the same as waiting.
- **Asking whether you were confirmed can track.** Until the answer is `true`, the redeemer's app asks the owner's server from time to time for up to 37 days after accepting, which tells that server roughly when the app is in use, and from what address, even after a decline. Apps keep to about once an hour and stop as soon as they know ([Section 8.2](#82-redeem)).
- **Domain hashis reveal affiliation.** `john#my.domain` tells people where John works. For personal use, a hashi on a provider's domain gives more privacy.
- **Check your devices.** Implementations **SHOULD** let owners list, and revoke in one step, every device, agent and grant, in case someone else set up or still has access to one of them.

---

## 14. IANA Considerations

This specification requests:

- the `hashi` URI scheme (provisional);
- the `hashi` well-known URI suffix;
- the media type `application/hashi+json`;
- the HTTP header fields `Hashi-Delegation` and `Hashi-Reply`; and
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
| **Telegram invite links** | A private invite link carries only a code, and can be set so that joining just sends a request, which an admin approves or dismisses. | Prior art for HASHI's offers, which only let someone ask, and for the owner confirming each redemption ([Section 8.7](#87-grants)). |
| **Bluesky avatars**, **Subresource Integrity**, **BIMI** | A Bluesky profile names its avatar by the image's hash. Subresource Integrity lets a web page give the hash of a script it loads, so the browser won't run a copy that whoever hosts it has changed. BIMI shows a brand's logo in email once the sender's domain enforces DMARC, and Gmail and Apple Mail also want a certificate showing the logo is the sender's, usually backed by a registered trademark. | Prior art for HASHI's picture: a link and the image's hash, signed by the owner ([Section 3.5](#35-pictures)). HASHI makes no brand check, so a picture is only ever decoration. The name follows the `picture` claim in OpenID Connect. |
| **Matrix and Bluesky sign-up**, **ACME** | Matrix and Bluesky sign people up on the server's own web page, with whatever checks that server wants. ACME, the protocol behind Let's Encrypt, approves a key made on the client through an outside check tied to that key. | Prior art for HASHI's sign-up: a check on the server's page, tied to the name and the HID, then a first publish signed by the new key ([Section 8.6](#86-publish)). |
| **Signal, AT Protocol, Matrix** | Keep a person's root key apart from working keys. | Prior art for HASHI's key roles. |
| **Apple configuration profiles**, **Chrome enterprise policies**, **1Password vaults** | Apple devices and Chrome fetch a signed settings file from a management server and check the signature before applying it. 1Password keeps vaults sealed on its servers, so it can't read them. | Prior art for the owner's rules: signed by the identity key, sealed to the inbox key and stored by a server that can't read them ([Section 8.8](#88-owners-rules)). |
| **Autocrypt**, **Keybase per-user keys**, **sops** | Autocrypt warns that if each of a person's mail apps makes its own key, mail to them can be read only by the app that sent the last message, so one app passes its key to the others. Keybase gives each account a key whose private half is encrypted for each of its devices, and revoking a device makes a new key for the devices that remain. sops keeps a file's key inside the file, encrypted for each person who may open it, and recommends a new key when someone is removed. | Prior art for the inbox key, its copies in the hashi document, and a new key whenever an agent is removed ([Section 9.1](#91-the-envelope)). |

**HASHI:** how I give you an address for me, how much I trust you, and how our agents reach each other even when they're offline.

## Appendix B: Open Questions

1. **Introductions:** a signed token by which a mutual contact vouches for a third party, and what level it may confer.
2. **Addressed offers:** a `for` field naming the recipient's HID, so a forwarded link is useless.
3. **Cancelling offers:** revoking outstanding multi-use offers before they expire.
4. **Changing hashi:** moving to a new hashi and telling existing contacts, without telling everyone.
5. **"Got a hashi?" hand-off:** for people with a hashi but no app, John's page asks for their hashi and sends the offer to an `accept` URL published in their hashi document, where their provider asks them to confirm (similar to Mastodon's remote follow).
6. **Profiles for moving to A2A or MCP** using HASHI agent keys.
7. **Recovery short of a reset** when an identity key is lost.
8. **Organisation-level policy** documents.
9. **Expressing an HID as a DID.**
10. **Read-aloud codes:** a code short enough to read out, for when even a short link won't do, such as over the phone. A short link's code ([Section 7.3](#73-short-links)) is too long for that, and a shorter one could be guessed unless the server limits tries much more tightly.

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
| RFC 8725 | JSON Web Token best current practices |
| RFC 9110 | HTTP semantics |
| RFC 9421 | HTTP message signatures |
| RFC 9530 | Digest fields |
| Unicode UAX #15 | Normalisation forms |
| [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Standard claims, including `picture` |
| [Subresource Integrity](https://www.w3.org/TR/SRI/) | Checking a fetched file against its hash |
| [A2A](https://a2a-protocol.org) | Agent2Agent protocol |
| [MCP](https://modelcontextprotocol.io/specification) | Model Context Protocol |
| [DID Core](https://www.w3.org/TR/did-core/) | Decentralised identifiers |
| [DIDComm Messaging v2](https://identity.foundation/didcomm-messaging/spec/v2.1/) | Encrypted agent messaging and mediators |
| [JMAP](https://www.rfc-editor.org/rfc/rfc8620) | RFC 8620, including its push model |
| [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) | Mapping Nostr keys to DNS identifiers |
| [Signal X3DH](https://signal.org/docs/specifications/x3dh/) | Signal key agreement |
| [AT Protocol](https://atproto.com/specs/did) | DID PLC and rotation keys |
| [Matrix](https://spec.matrix.org/latest/client-server-api/#cross-signing) | Cross-signing |
| [Autocrypt Level 1](https://docs.autocrypt.org/level1.html) | One email key shared across a person's mail apps |
| [Keybase per-user keys](https://book.keybase.io/docs/teams/puk) | A per-account key encrypted for each device |
| [sops key management](https://getsops.io/docs/usage/key-management/) | A file's key encrypted for each person who may open it |
