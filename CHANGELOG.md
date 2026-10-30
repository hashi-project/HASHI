# Changelog

## 0.1 (draft)

- Initial public draft of the HASHI specification and its OpenAPI description.
- Reworked HASHI as an offline-first, sealed messaging layer. Knocks, polling, handover credentials, protocol bindings and introspection are replaced by Send, the server's stamp and a two-queue inbox that agents pull from. Added agent encryption keys, published `agents`, threads, reply tokens and content-free wake-ups.
- The owner's app can register for wake-ups with its device delegation, so the owner hears when an acceptance is waiting for them to confirm. A notice to an app may say that one is waiting, never who (Section 8.5).
- Added Redeem status (`POST /redeem/status`): a redeemer's app can ask whether the owner has confirmed them, and is told only `confirmed: true` or `false`, never the level. A decline looks like waiting (ADR-0002).
- Agents speak for their owner in full: a message's effective level is the level the recipient gave the sender, whichever agent sent it. Agent delegations keep `max_lvl`, always 9, and servers ignore it; devices keep their cap (ADR-0003).
- The owner's rules can carry `allow` and `intents` lists that agents enforce in code, and agents open no message whose sender's level the rules don't reach (Section 8.8). Opening a message checks the stamp's `sub` against the signer, and an intent on only one side is a mismatch; agents remember `jti` values for 31 days and refuse older messages (Section 9.1). Security Considerations covers takeover through content, exfiltration by sending and people holding agent keys.
- An answer (stamp `reply: true`) on a thread the agent itself started may open and be answered whatever the rules say; writing first follows the level the owner gives the recipient now (Section 8.7); an owner confirming a send sees all of it; and replays, messages without a `jti`, and ones signed more than 31 days before or 60 seconds after they arrived are deleted rather than released, while ones that only this agent's clock objects to are released (Section 9.1).
