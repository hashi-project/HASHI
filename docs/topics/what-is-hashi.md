# What is HASHI?

## The Problem

More and more, people hand correspondence, scheduling and negotiation to AI agents. Agent protocols such as A2A let agents talk to each other, but they leave four questions unanswered:

1. **Where do I reach your agent?** There's no address you can hand someone, the way you'd hand out an email address or phone number.
2. **Who gets through?** There's no shared way for a person to say "my friends can book time, strangers can't."
3. **How does trust carry over?** If you meet someone in the street and decide to trust them, their agent has no way to prove it's acting for that person.
4. **What if your agent is offline?** A personal agent on a phone or laptop sits behind a home or mobile network, often asleep, and nobody can reach into it from the internet.

## The Idea

HASHI answers all four, the way an email address, an address book and a mail server do for email.

- **A hashi is your address.** It looks like `john#my.domain`, and you can say it aloud: *"john hash my dot domain"*.
- **Offers let people in.** You share a QR code or link. When someone accepts it, you decide whether to let them in, and at what trust level. Their app normally offers one back, so confirming them connects you both ways.
- **Trust belongs to people, not software.** Once Sarah accepts John's offer and he confirms her, the trust is tied to Sarah herself. She can change her agent, phone or provider and keep it.
- **Your server holds your mail.** When Sarah's agent sends John a message, John's HASHI server checks who it is and what she's allowed, stamps the message with her trust level and puts it in John's inbox. John's agent picks it up when it comes online and replies the same way.
- **Sealed, not read.** Messages are encrypted end to end to John's agents. His server can vouch for who sent them, but can't read them.

## What HASHI Is Not

- **Not an agent protocol.** It carries agents' messages but gives them no meaning. Agents that can reach each other directly can move to A2A or similar.
- **Not a login system.** It doesn't sign you into websites or verify your legal identity.
- **Not a rulebook for agents.** HASHI doesn't say what any trust level allows. That's up to you, and your HASHI server can keep your rules for your agents without being able to read them.

## Like Email

You need a hashi to be reached, just as you need an email address to receive email, and like email your messages wait on your server until you collect them. When someone without one opens your link, the page asks *"Got a hashi?"* and points them to where they can get one.

## Next

- [Key Concepts](key-concepts.md)
- [HASHI and A2A](hashi-and-a2a.md)
- [Specification](../specification.md)
