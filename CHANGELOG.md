# Changelog

## 0.1 (draft)

- Initial public draft of the HASHI specification and its OpenAPI description.
- Reworked HASHI as an offline-first, sealed messaging layer. Knocks, polling, handover credentials, protocol bindings and introspection are replaced by Send, the server's stamp and a two-queue inbox that agents pull from. Added agent encryption keys, published `agents`, threads, reply tokens and content-free wake-ups.
- The owner's app can register for wake-ups with its device delegation, so the owner hears when an acceptance is waiting for them to confirm. A notice to an app may say that one is waiting, never who (Section 8.5).
- Added Redeem status (`POST /redeem/status`): a redeemer's app can ask whether the owner has confirmed them, and is told only `confirmed: true` or `false`, never the level. A decline looks like waiting (ADR-0002).
- Agents speak for their owner in full: a message's effective level is the level the recipient gave the sender, whichever agent sent it. Agent delegations keep `max_lvl`, always 9, and servers ignore it; devices keep their cap (ADR-0003).
