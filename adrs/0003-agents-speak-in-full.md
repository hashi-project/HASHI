# ADR-0003: Agents speak for their owner in full

**Status:** Accepted

**Date:** 2026-10-25

**Decision Makers:** Rob

## Context

Every delegation carried `max_lvl`. For a device it caps how high that device can raise a grant. For an agent it capped the level its messages arrived at: the effective level was the lower of the recipient's grant and the sending agent's `max_lvl` ([Section 6.3](../docs/specification.md#63-effective-level)). Pairing an agent meant picking that level.

An owner either trusts an agent to act for them or doesn't pair it. A second trust level on top of the one other people give the owner is confusing to explain and to choose, and nobody asked for it.

## Considered Options

- Keep the agent cap, defaulting to 9 and hiding it.
- Drop the agent cap: an agent's messages arrive at the level the recipient gave its owner.

## Decision

**Chosen option:** "Drop the agent cap"

The only trust level that matters for a message is the one the recipient gave its sender. Each agent's own behaviour is governed by the owner's rules ([Section 8.8](../docs/specification.md#88-owners-rules)), not by a level.

`max_lvl` stays in agent delegations, always 9, so connectors and servers that still require the field keep accepting them. Servers ignore it for agents. Device delegations keep their `max_lvl`.

## Consequences

### Positive

- Pairing an agent asks nothing about levels.
- One level per relationship, set by the other person, is all there is to understand.

### Negative

- A stolen agent key speaks for the owner at every level others have given them until it's revoked or expires. Removing an agent quickly matters more.
- An owner can no longer pair a narrow, low-stakes agent whose messages carry less weight. They'd need a separate hashi for that.

## Specification Changes

- Section 5.3: `max_lvl` is the device's grant cap. For agents it's always 9 and ignored.
- Section 6.3: the effective level is the recorded grant. Servers must not lower it because of the sending agent.
- Section 13: stolen agent keys are no longer limited by `max_lvl`.
- The OpenAPI description is unchanged: it only uses `max_lvl` for devices.
