# ADR-0001: Recoverable Identity Keys and Detectable Takeovers

**Status:** Accepted

**Date:** 2026-10-06

**Decision Makers:** Rob Cleghorn

**Related Issue:** None

## Context

In v0.1, whoever holds a hashi's identity key can rotate it, and verifiers accept the rotation silently. A thief who steals the key can rotate first and take over the HID, along with every grant other people have given it. The owner's only way out is a reset, which costs them every relationship. If owner and thief both rotate, the specification doesn't say which chain wins.

Other identity systems have already solved this, notably KERI, did:webvh and did:plc.

## Considered Options

- Adopt an existing DID method (did:webvh) wholesale.
- Borrow proven techniques from KERI and did:webvh into HASHI's own formats.
- Keep the current design and rely on reset.

## Decision

**Chosen option:** "Borrow proven techniques into HASHI's own formats"

HASHI's identity layer follows these principles:

1. **Holding the current key isn't enough to change who you are.** The right to rotate is committed to in advance and kept apart from the key used day to day (pre-rotation).
2. **The identifier commits to its recovery path from the start,** so a thief can't rewrite it.
3. **Conflicting histories are never settled silently.** Verifiers accept neither, warn their user, and drop trust to level 0.
4. **Reuse proven designs, but not at the cost of core goals:** hardware-backed keys on phones, compact JOSE, and small, quick-to-verify documents.
5. **Stay close to did:webvh,** so that HASHI can become a profile of it if it later fits.

did:webvh v1.0 was not adopted outright because it conflicts with principle 4: it accepts only Ed25519 keys for identity changes (phone hardware holds P-256), its log grows with every change, and its next version is planned to break the format.

## Consequences

### Positive

- Losing or leaking the everyday identity key is recoverable without a reset.
- Takeover attempts that create competing histories are detected.
- Hardware-backed keys and JOSE are kept.

### Negative

- Owners must safeguard a second secret from the start.
- Whoever steals the committed recovery key can still take over.
- A host can show a different history to someone meeting the identity for the first time; only a transparency log would catch that.
- HIDs are derived differently, so v0.1 HIDs aren't compatible.
- The combination needs independent security review.

## Specification Changes

Sections 2, 4.2 to 4.5, 5.2, 5.4, 5.5, 7.1, 12 and Appendices A and B of `docs/specification.md`, and the `HashiDocument` schema in `specification/hashi-openapi.yaml`.

## References

- [KERI specification](https://trustoverip.github.io/tswg-keri-specification/)
- [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
- [did:plc specification](https://web.plc.directory/spec/v0.1/did-plc)
