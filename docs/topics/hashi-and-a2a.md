# HASHI and A2A

HASHI and [A2A](https://a2a-protocol.org) do different jobs and fit together.

| | HASHI | A2A |
|---|---|---|
| **Question it answers** | Who are you, and should you get through? | What should our agents say and do? |
| **Carries** | Addresses, keys, signed tokens | Messages, tasks and artifacts |
| **When** | Before the conversation | During the conversation |

A2A expects credentials to be obtained separately, out of band. HASHI is one way to get them, grounded in a relationship between two people.

## The Handover

1. Sarah's agent knocks on John's HASHI server and lists the protocols it speaks, for example `a2a/1.0`.
2. John's server checks Sarah's identity and trust level, and picks `a2a/1.0`.
3. It answers `yeah` with John's A2A endpoint and a credential: a short-lived JWT signed by John's server, naming John's agent as its audience, carrying Sarah's trust level, and bound to Sarah's agent key.
4. Sarah's agent calls John's A2A agent, presenting the credential and proving it holds the matching key on every request.
5. John's agent checks the credential and decides what Sarah may do at that level.

Credentials last at most 15 minutes. Longer conversations knock again, so a lowered trust level takes effect quickly.

## Other Protocols

HASHI isn't tied to A2A. Each agent protocol gets a binding that defines what its credential looks like. An MCP binding is planned; MCP's OAuth-based authorisation means it needs more design work. See the [Roadmap](../roadmap.md).

For the full details, see section 9 of the [Specification](../specification.md).
