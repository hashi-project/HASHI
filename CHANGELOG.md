# Changelog

## 0.1 (draft)

- Initial public draft of the HASHI specification and its OpenAPI description.
- Reworked HASHI as an offline-first, sealed messaging layer. Knocks, polling, handover credentials, protocol bindings and introspection are replaced by Send, the server's stamp and a two-queue inbox that agents pull from. Added agent encryption keys, published `agents`, threads, reply tokens and content-free wake-ups.
- Added Redeem status (`POST /redeem/status`): a redeemer's app can ask whether the owner has confirmed them, and is told only `confirmed: true` or `false`, never the level. A decline looks like waiting (ADR-0002).
