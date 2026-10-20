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
| Server key | The owner's HASHI server | Signing grants and stamps. |
| Agent key | An agent or app acting for the owner | Signing redeems, messages and reply tokens. |
| Encryption key | Each agent | Opening messages sealed to that agent. |

Losing a phone means revoking that phone's key, not rebuilding your identity.

## Trust Levels

An integer from **0** (public) to **9** (highest). Trust is directional: the level John gives Sarah is separate from the level Sarah gives John. Only 0 and 9 have fixed meanings; what levels 1 to 8 unlock is up to the owner's software.

Lowering a level takes effect immediately and needs nobody's agreement. Raising one needs a new offer.

## Offer

A signed invitation, usually a QR code or link, saying "whoever redeems this may get up to level N". Offers are usually one-time and short-lived, and travel in the part of the link that never reaches a server.

## Grant

The level a HASHI server has recorded for a particular person (HID). The server's record is always authoritative.

## Message

A signed request from someone's agent to your HASHI server, carrying a sealed **envelope**: content encrypted end to end to your agents and signed by the sender. Outside the envelope there's only who sent it, an `intent` such as `schedule`, and a thread ID. Messages from strangers (level 0) carry no content at all.

The answer is one of:

| Result | Meaning |
|--------|---------|
| `yea` | Stamped and queued. Says nothing about when an agent will act on it. |
| `nah` | Not accepted. No reason given. |

## Stamp

Your server's signed note on each message it accepts: who sent it, at what trust level, with what intent, and when. Your agents trust the level because the stamp is signed, not because they trust the queue.

## Inbox

Your two queues on your HASHI server: **incoming** and **processing**. The server doesn't route. Each of your agents looks at the inbox when it comes online, or when a content-free push wakes it, claims what's for it (the first claim wins), and deletes it when it's done. Anything left untouched expires.

## Threads and Reply Tokens

A conversation is a **thread**: every reply repeats the thread ID, like an email reply. A reply is sealed only to the agent that asked, so it reaches the right one. Trust is one-way, so a first message carries a **reply token** that lets the other person answer on that thread even if you've never granted them a level.
