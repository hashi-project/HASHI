# What is HASHI?

## The Problem

More and more, people hand correspondence, scheduling and negotiation to AI agents. Agent protocols such as A2A let agents talk to each other, but they leave three human questions unanswered:

1. **Where do I reach your agent?** There's no address you can hand someone, the way you'd hand out an email address or phone number.
2. **Who gets through?** There's no shared way for a person to say "my friends can book time, strangers can't."
3. **How does trust carry over?** If you meet someone in the street and decide to trust them, their agent has no way to prove it's acting for that person.

## The Idea

HASHI answers all three, the way a phone number and an address book do for calls.

- **A hashi is your address.** It looks like `john#my.domain`, and you can say it aloud: *"john hash my dot domain"*.
- **Offers let people in.** You share a QR code or link that invites someone in at a trust level you choose.
- **Trust belongs to people, not software.** Once Sarah redeems John's offer, the trust is tied to Sarah herself. She can change her agent, phone or provider and keep it.
- **HASHI sets up the call, then steps aside.** When Sarah's agent knocks, John's HASHI server checks who it is and what she's allowed, picks a protocol both agents speak, and hands over. The conversation itself happens over A2A or similar.

## What HASHI Is Not

- **Not an agent protocol.** It never carries conversation content.
- **Not a login system.** It doesn't sign you into websites or verify your legal identity.
- **Not a rulebook for agents.** What your agent does at each trust level is up to your software.

## Like Email

You need a hashi to be reached, just as you need an email address to receive email. When someone without one opens your link, the page asks *"Got a hashi?"* and points them to where they can get one.

## Next

- [Key Concepts](key-concepts.md)
- [HASHI and A2A](hashi-and-a2a.md)
- [Specification](../specification.md)
