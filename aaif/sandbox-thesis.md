# HASHI: a thesis for AAIF Sandbox

## The problem

AI agents increasingly act for people: they book, buy, negotiate and coordinate. Today an agent that wants to reach *your* agent has no address to use and no way to know who it's dealing with. The fallbacks are email, which anyone can spoof and which agents can't safely act on, and platform-specific integrations, which only work inside one vendor's walls. There is no open, person-centred way to say "this is where my agents can be reached, and this is how far I trust you."

## What HASHI is

HASHI (Human Agent Secure Handshake Interface) is an open specification for exactly that. A person gets a **hashi**, an address like `john#my.domain`, that they hand out like an email address. When someone's agent wants to reach theirs:

- the message is **sealed end to end**, so servers carry it but can't read it;
- the server **stamps it with the trust level** the recipient has given the sender, from 0 (stranger) to 9, so the recipient's agent knows how far it may act;
- trust is created only by a **handshake that a person confirms**, never by an agent, so prompt injection can't create a relationship;
- the recipient's **own rules**, signed by them, tell their agents what each trust level allows;
- every agent can **prove whose hashi it speaks for**, through delegations signed by the owner's identity key.

Agents pull from an inbox, so an agent on a laptop that sleeps half the day still works. Anyone can run a HASHI server for their own domain, as with email.

## Who would use it

- **People with personal AI agents** (Claude, ChatGPT, Codex, OpenClaw and others) who want those agents to coordinate with friends', colleagues' and businesses' agents without handing over their inbox or calendar.
- **Businesses** that want customers' agents to reach their agents (bookings, support, orders) with verified identity and a clear trust level, instead of scraping web forms.
- **Agent and platform builders** who need an identity and permission layer between agents that they don't have to own. HASHI's agent connector is an MCP server, so any MCP-capable agent can use it today.

## Why it matters before adoption

Agent-to-agent protocols mostly answer *how* agents talk. HASHI answers *who* is behind an agent and *how much they're trusted*, decided by people. That layer is easiest to standardise neutrally **before** each platform builds its own walled version. Early neutral governance under AAIF would keep person-to-person agent trust an open commons rather than a feature of whichever platform wins.

## Where it is today

- Specification v0.1 (draft), Apache-2.0, with an OpenAPI description and Architecture Decision Records.
- A working server running at myhashi.org, mobile apps for iOS and Android in public beta, and an agent connector (MCP server) used with Claude Code, Codex and OpenClaw. The connector is open source under Apache-2.0 as the reference implementation of the agent side. The server and apps are Ocean Labs' own implementation of the specification, which is written so others can implement it independently.
- One maintainer so far, with a documented intent in GOVERNANCE.md to move to a multi-maintainer model.

## What would justify Growth

- At least two unaffiliated organisations running HASHI in production: their own server, or agents that receive real traffic through a hashi.
- A second independent implementation of the server or the agent side, built from the specification alone.
- Committers from at least two organisations over six months, with a written committer-acceptance process.
- A 1.0 of the specification, with conformance tests that implementations run in CI.
