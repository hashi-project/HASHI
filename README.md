# HASHI

**Human Agent Secure Handshake Interface**

> *Got a hashi?*

HASHI is an open specification for giving people an address their AI agents can be reached at, and for deciding who gets through.

A **hashi** looks like `john#my.domain`. You hand it out the way you'd hand out an email address or phone number. When someone's agent wants to reach yours, it sends a sealed message to your HASHI server. The server checks who they are, stamps the message with the trust level you've given them and puts it in your inbox. Your agent picks it up whenever it's online, even if it lives on a laptop that's asleep half the day, and replies the same way.

## Principles

1. **People connect. Agents get to work.** Once we've agreed to work together, our agents can take it from there, collaborating, solving problems and making progress without us needing to be involved in every conversation.
2. **Know who's behind every agent.** Every agent can prove whose hashi it speaks for. If you've met them and swapped hashis, you know exactly who you're dealing with, even when their agent is doing the talking.
3. **Trust stays in human hands.** We decide who we trust, how far their agents can go with us, and how much freedom we give our own. The relationships are human. The work can be autonomous.
4. **Private, secure and always ready.** Conversations stay protected end to end. Messages get through even when we're offline, so work can keep moving whenever we're ready.
5. **An open network that belongs to everyone.** Anyone can run a server. Any app can connect to any server. Your hashi works like an email address, an identity you can use across an open network, without a company controlling who can participate.

## Why HASHI?

The early internet was designed to be open. Anyone could run a mail server or a website, and the address told you where to go. Today most of how we reach each other runs through a reducing number of companies, away from the original open design and into products.

AI agents are about to do a lot of stuff on our behalf. HASHI puts control of that back with people. You hold the address, you decide who gets through and how far, and any server or app that follows the spec can take part.

Agent protocols like A2A cover how agents talk to each other. They don't cover how you give your agents an address, how you decide who can reach them, or how a message gets to an agent on a laptop that's asleep half the day. That's the gap HASHI fills.

## How the Network Fits Together

The part after the `#` is a domain name. To reach `john#my.domain`, an app looks up `my.domain` in DNS like any other website, then asks that domain's HASHI server for John's details at `https://my.domain/.well-known/hashi/john`. Email works the same way: the domain decides which server handles its mail.

So you can run a server on your own domain, or get a hashi from someone who already runs one, like myhashi.org. One domain can hold as many hashis as it likes, so nobody needs a DNS record of their own.

## Key Features

- **Directional trust levels from 0 to 9.** Level 0 is public, 9 is highest, and what 1 to 8 unlock is up to the owner's software.
- **Signed offers.** A QR code or link invites someone in. You choose their trust level when you confirm them, and their app normally offers one back, so you're connected both ways.
- **Relationships outlast the tech.** Agents, devices, keys and providers can all change without breaking a relationship.
- **Agents only connect out.** Nobody needs to reach into a phone or laptop. Agents pick messages up from their own HASHI server.
- **Plain web standards.** HTTPS and standard JOSE signatures and encryption.

## How It Works

1. John shows Sarah a QR code containing a signed **offer**.
2. Sarah's HASHI app **redeems** it and sends an offer of her own back. When John confirms her on his phone and picks level 4, his server records a **grant** for Sarah's identity, and the same tap redeems her offer, so they're connected both ways.
3. Later, Sarah's agent **sends** John a sealed message. John's server checks her identity and grant, **stamps** it at level 4 and queues it in John's **inbox**.
4. John's agent comes online, picks the message up and replies to Sarah's server on the same thread. If both agents can reach each other directly, they can agree to carry on over [A2A](https://a2a-protocol.org) or another protocol.

## Get Started

**Try it.** [myhashi.org](https://myhashi.org) is in closed beta testing. If you'd like to take part, get in touch by [opening an issue](https://github.com/hashi-project/HASHI/issues).

**Read the spec.**

- [Specification](docs/specification.md)
- [What is HASHI?](docs/topics/what-is-hashi.md) and [Key Concepts](docs/topics/key-concepts.md)
- The HTTP API in [`specification/hashi-openapi.yaml`](specification/hashi-openapi.yaml)
- Open questions on the [Roadmap](docs/roadmap.md)

## Status

Version **0.1** of the spec is published. myhashi.org and the phone app are in closed beta testing. It's all still experimental, so expect breaking changes.

## Contributing

Feedback and proposals are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[Apache License 2.0](LICENSE).
