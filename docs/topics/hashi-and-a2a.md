# HASHI and A2A

HASHI and [A2A](https://a2a-protocol.org) do different jobs and fit together.

| | HASHI | A2A |
|---|---|---|
| **Question it answers** | Who are you, should you get through, and how do I reach you if you're offline? | What should our agents say and do, live? |
| **Carries** | Addresses, keys, signed tokens and sealed messages | Messages, tasks and artifacts |
| **Needs** | Each agent to connect out to its own HASHI server | Both agents reachable from the internet at the same time |

A2A assumes both agents have an endpoint the other can reach. A personal agent on a phone or laptop usually doesn't: it's behind a home or mobile network and often asleep. HASHI works anyway, because agents only ever connect out to their own server and pick messages up when they're online.

## Moving to A2A

Agents that can reach each other directly, for example two cloud-hosted agents, can agree inside their HASHI messages to carry on over A2A. HASHI doesn't define how, and doesn't hand out A2A credentials. When agents do move, they should authenticate each other with their HASHI agent keys, which chain back to each person's identity, so the people behind them stay the people HASHI checked.

## Other Protocols

The same goes for MCP or any other protocol. Profiles for moving to A2A or MCP using HASHI keys are an open question on the [Roadmap](../roadmap.md).

For the full details, see section 9 of the [Specification](../specification.md).
