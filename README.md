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

Agent protocols like A2A define how agents talk to each other. They don't define:

- how a person gives their agents an address others can use;
- how that person decides who may reach them, and with how much trust; or
- how trust formed between two people, say on meeting in the street, carries across to their agents; or
- how a message reaches an agent that's offline or can't be reached from the internet.

HASHI fills that gap. It's the address book, the front door and the letterbox.

## Key Features

- **Directional trust levels from 0 to 9.** Level 0 is public, 9 is highest, and what 1 to 8 unlock is up to the owner's software.
- **Signed offers.** A QR code or link invites someone in, up to a trust level you choose.
- **Relationships outlast the tech.** Agents, devices, keys and providers can all change without breaking a relationship.
- **Agents only connect out.** Nobody needs to reach into a phone or laptop. Agents pick messages up from their own HASHI server.
- **Plain web standards.** HTTPS, standard JOSE signatures and encryption, and no per-user DNS.

## How It Works

1. John shows Sarah a QR code containing a signed **offer** at trust level 4.
2. Sarah's HASHI app **redeems** it. John's server records a **grant** for Sarah's identity.
3. Later, Sarah's agent **sends** John a sealed message. John's server checks her identity and grant, **stamps** it at level 4 and queues it in John's **inbox**.
4. John's agent comes online, picks the message up and replies to Sarah's server on the same thread. If both agents can reach each other directly, they can agree to carry on over [A2A](https://a2a-protocol.org) or another protocol.

## Get Started

- 📖 Read the [Specification](docs/specification.md).
- 🧭 Start with [What is HASHI?](docs/topics/what-is-hashi.md) and [Key Concepts](docs/topics/key-concepts.md).
- 🔌 See the HTTP API in [`specification/hashi-openapi.yaml`](specification/hashi-openapi.yaml).
- 🗺️ Check the [Roadmap](docs/roadmap.md) for open questions.

## Status

Version **0.1**, draft, experimental. Expect breaking changes.

## Contributing

Feedback and proposals are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[Apache License 2.0](LICENSE).
