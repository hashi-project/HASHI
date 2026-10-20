# Key Concepts

## Hashi

A hashi is an address of the form `local#domain`, such as `john#my.domain`. It identifies and locates a person. On its own, a hashi carries no trust.

For software, the same address is written `hashi://my.domain/john`. For QR codes and links, it's `https://my.domain/.well-known/hashi/john`, which any phone camera can open.

Looking up a hashi fetches its **hashi document**, which the owner signs. It lists their keys, their agents, where to send them messages and whether they'll hear from strangers.

## HID

The HID, or **hashi ID**, is a stable identifier derived from a person's first identity key. It survives renaming, changing provider and rotating keys. Relationships are recorded against HIDs.

## Keys

| Key | Held by | Used for |
|-----|---------|----------|
| Identity key | The owner, who keeps it somewhere safe | Signing the hashi document, the owner's device and agent keys, and the owner's rules. The root of everything. |
| Device key | Each of the owner's devices, such as their phone | Signing offers, accepting other people's offers and confirming people who accept the owner's. |
| Server key | The owner's HASHI server | Signing stamps, and regular statements that the hashi document is current. |
| Agent key | Each agent acting for the owner | Signing messages and reply tokens. |
| Inbox key | The owner's agents, each with its own copy | Opening messages. Every message to the owner is sealed to it. |

Losing a phone means revoking that phone's key, not rebuilding the owner's identity. Removing an agent shuts it out of the owner's inbox and replaces the inbox key.

## Trust Levels

A trust level is a number from **0** (public) to **9** (highest). Trust is directional: the level John gives Sarah is separate from the level Sarah gives John. Only 0 and 9 have fixed meanings; what levels 1 to 8 unlock is up to the owner.

Lowering a level takes effect immediately and needs nobody's agreement. Raising someone's level happens only when they accept one of the owner's offers and the owner then confirms them.

## Offer

An offer is a signed invitation, usually shared as a QR code or link. It's often called a handshake. In the spec, accepting an offer is called redeeming it. Only a person can accept an offer, in their own app; agents can't. Nothing changes unless the owner who made the offer confirms them and picks their level. Accepting normally sends an offer back, so one meeting can set up trust both ways. Offers are usually one-time and short-lived.

## Grant

A grant is the level a HASHI server has recorded for a particular person (HID). Until the owner confirms someone who has accepted an offer, that person keeps whatever level they had before.

## Owner's Rules

The owner's rules say in plain words what their agents may do for someone at each level. A rule for level 2 might say, "Can ask when I'm free and arrange a coffee." A rule for one level also covers every level above it, and a level that no rule reaches allows nothing. The rules are signed by the owner's identity key and sealed to the inbox key, so the server keeps them but can't read or change them. Agents check them before acting on a message.

## Message

A message is a signed request from someone's agent to your HASHI server, carrying a sealed **envelope**: content the sender signs and then encrypts to your inbox key, so only your agents can open it. Outside the envelope there's no free text, just who it's from and to, a thread ID, an optional `intent` such as `schedule`, and any reply token.

Your server answers every message with one of two results:

| Result | Meaning |
|--------|---------|
| `yea` | The message was stamped and queued. This says nothing about whether, or when, an agent will act on it. |
| `nah` | The message wasn't accepted, and no reason is given. |

Strangers (level 0) get `nah` unless you've chosen to hear from them, and even then they can send only a short message of a few hundred words. Someone replying with a reply token from one of your agents gets through whether or not you've chosen to hear from strangers.

## Stamp

A stamp is your server's signed note on each message it accepts: who sent it, at what trust level, with what intent, and when. Your agents can rely on that level because your server signed it, not just because the message turned up in your inbox.

## Inbox

Your inbox is two queues on your HASHI server: **incoming** and **processing**. The server doesn't decide which agent gets what. Each of your agents checks the inbox when it comes online, or when a content-free push notification wakes it, and claims the messages it decides to handle. The first claim wins. An agent deletes a message once it has dealt with it, and anything left behind expires within 30 days.

## Threads and Reply Tokens

A conversation is a **thread**: every reply repeats the thread ID, like an email reply. When Sarah's agent writes to John, he may have no grant from her. So her first message can carry a **reply token**, which lets him answer on that thread at whatever level he already has with her, even 0. His reply is sealed to Sarah's inbox key, like every message, so if the agent that wrote to him has stopped, another of her agents can pick it up.
