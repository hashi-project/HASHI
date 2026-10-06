# Key Concepts

## Hashi

An address of the form `local#domain`, such as `john#my.domain`. It identifies and locates a person. A bare hashi carries no trust.

For software, the same address is written `hashi://my.domain/john`. For QR codes and links, it's `https://my.domain/.well-known/hashi/john`, which any phone camera can open.

## HID

The **hashi ID**: a stable identifier derived from a person's first identity key. It survives renaming, changing provider and rotating keys. Relationships are recorded against HIDs.

## Keys

| Key | Held by | Used for |
|-----|---------|----------|
| Identity key | The owner, kept safe | Signing the binding, delegations and rotations. The root of everything. |
| Device key | The owner's phone | Signing offers. |
| Server key | The owner's HASHI server | Signing grants and handover credentials. |
| Agent key | An agent or app acting for the owner | Signing redeems and knocks. |

Losing a phone means revoking that phone's key, not rebuilding your identity.

## Trust Levels

An integer from **0** (public) to **9** (highest). Trust is directional: the level John gives Sarah is separate from the level Sarah gives John. Only 0 and 9 have fixed meanings; what levels 1 to 8 unlock is up to the owner's software.

Lowering a level takes effect immediately and needs nobody's agreement. Raising one needs a new offer.

## Offer

A signed invitation, usually a QR code or link, saying "whoever redeems this may get up to level N". Offers are usually one-time and short-lived, and travel in the part of the link that never reaches a server.

## Grant

The level a HASHI server has recorded for a particular person (HID). The server's record is always authoritative.

## Knock

A signed request from someone's agent to reach yours. The answer is one of:

| Result | Meaning |
|--------|---------|
| `yeah` | Accepted. A handover follows. |
| `yeah-nah` | Waiting on the owner. Check back shortly. |
| `nah` | Not accepted. No reason given. |

## Handover

The answer to an accepted knock: which protocol to use, where the owner's agent is, and a short-lived credential bound to the requester's key. After that, HASHI is out of the picture.
