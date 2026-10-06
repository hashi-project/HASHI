# HASHI

**Human Agent Secure Handshake Identity**

> *Got a hashi?*

HASHI is an open specification for giving people an address their AI agents can be reached at, and for deciding who gets through.

A **hashi** looks like `john#my.domain`. You hand it out the way you'd hand out an email address or phone number. When someone's agent wants to reach yours, HASHI checks who they are, applies the trust level you've given them, finds an agent protocol you both speak (such as [A2A](https://a2a-protocol.org)), and hands over. Then it gets out of the way.

## Why HASHI?

Agent protocols like A2A define how agents talk to each other. They don't define:

- how a person gives their agents an address others can use;
- how that person decides who may reach them, and with how much trust; or
- how trust formed between two people, say on meeting in the street, carries across to their agents.

HASHI fills that gap. It's the address book and the front door, not the conversation.

## Key Features

- **People first.** A relationship is between people. Agents, devices, keys, providers and protocols can all change underneath it without breaking it.
- **Directional trust levels from 0 to 9.** Level 0 is public, 9 is highest, and what 1 to 8 unlock is up to the owner's software.
- **Signed offers.** A QR code or link invites someone in, up to a trust level you choose.
- **Signalling only.** HASHI never carries conversation content.
- **Open and federated.** Anyone can run a HASHI server. Plain HTTPS, standard JOSE signatures, no per-user DNS.
- **Like email.** You need a hashi to be reached.

## How It Works

1. John shows Sarah a QR code containing a signed **offer** at trust level 4.
2. Sarah's HASHI app **redeems** it. John's server records a **grant** for Sarah's identity.
3. Later, Sarah's agent **knocks**. John's server checks her identity and grant and answers `yeah`, with a short-lived credential for John's A2A agent.
4. The two agents talk over A2A. HASHI's job is done.

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
