# ADR-0002: Tell a redeemer only whether they were confirmed

**Status:** Accepted

**Date:** 2026-10-24

**Decision Makers:** Rob

## Context

Redeeming an offer leaves a pending acceptance on the owner's server, and nothing changes until the owner confirms it and picks a level ([Section 8.7](../docs/specification.md#87-grants)). Redeem answers 202 with no body, and the specification deliberately tells the redeemer nothing about what happens next.

That left the redeemer's app guessing. In testing, an app showed "you can reach them" for someone who had never confirmed, so it now shows that it's waiting instead. But the only sign it ever gets is the owner redeeming the offer it sent back, which happens only when the owner accepts that too. Otherwise "waiting" never clears, even once the owner has confirmed.

## Considered Options

- **Keep telling the redeemer nothing.** The app can only say "waiting" until 30 days pass.
- **A push from the owner's server when the owner confirms.** The redeemer's devices register with the redeemer's own server, not the owner's, so this works only when both hashis are on the same server, unless servers start delivering to each other. It also hands Apple or Google the fact that a confirmation happened.
- **A status the redeemer's app asks for, saying pending, confirmed or declined.** Works between any two servers, but tells the redeemer that the owner said no.
- **A status that says only confirmed or not.** Works between any two servers, and a decline looks the same as waiting.

## Decision

**Chosen option:** "A status that says only confirmed or not"

`POST {endpoint}/redeem/status` on the owner's server, signed by one of the redeemer's devices like Redeem, answers `{ "confirmed": true }` when the owner records a level of 1 or more for the caller's HID and hasn't refused it, and `false` in every other case.

**Why the level stays hidden.** A level means something only to the owner's own agents ([Section 6.2](../docs/specification.md#62-rules), rule 3). Telling someone "you're a 2, not a 4" invites them to ask why, or to sound someone out by how they're ranked. That's why offers name no level and the specification says nothing tells a redeemer the level ([Section 13](../docs/specification.md#13-privacy-and-safety)). Whether the level is at least 1 is different: a full-size send already succeeds only from level 1 up and gets `nah` below it ([Section 8.3](../docs/specification.md#83-send)), so anyone can find it out by sending. The status adds nothing to what the redeemer could already learn. It only saves them from having to send something to find out.

**Why a decline looks like waiting.** A decline, a refusal and an acceptance dropped after 30 days all answer `false`, just like one still waiting. That keeps "a `nah` is just a `nah`" ([Section 6.4](../docs/specification.md#64-zero-is-zero)): the owner can ignore or decline someone without the app telling them so straight away, and a refused HID can't tell it was singled out. The redeemer's app shows "waiting" until 30 days pass, then "not confirmed".

**Why it isn't signed.** It only decides whether the app shows a tick. A server that lied could equally answer `yea` to sends, so a signature would protect nothing that matters. HTTPS to the owner's endpoint is enough.

**Why not a push as well.** Across servers it would need server-to-server delivery, which HASHI doesn't have. A same-server push could come later as an optional nudge to ask, without changing this call.

## Consequences

### Positive

- The redeemer's app can show "you can reach them" as soon as it next asks after the owner confirms, between any two servers.
- The redeemer learns nothing new: not the level, not a decline and not a refusal.

### Negative

- It's a poll. The app learns of a confirmation only when it next asks (on unlock or refresh, at most about hourly per acceptance), not the moment it happens.
- Asking discloses something to the owner's server: until the redeemer is confirmed, for up to 30 days, it sees roughly when the redeemer's app is in use, and from what address, even after a decline. That's why apps ask at most about hourly, count failed asks too, and stop as soon as they know. Section 13 says so.
- One more call for servers to rate-limit.
- A decline keeps showing as waiting for up to 30 days.

## Specification Changes

- `docs/specification.md`: Section 8 operations table; Section 8.2 ("Finding out it was confirmed"); Section 5.3 (role checks); Section 8.9 (403 and 404); Section 13 ("Offers carry only the issuer's own details", and "Asking whether you were confirmed can track").
- `specification/hashi-openapi.yaml`: `/redeem/status`, `RedeemStatusRequest`, `RedeemStatus`.
