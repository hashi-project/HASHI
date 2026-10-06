# Roadmap

HASHI is at version 0.1, a draft. These are the open questions, also listed in Appendix B of the [Specification](specification.md). Discussion is welcome in issues.

## Open Questions

1. **Introductions.** A signed token by which a mutual contact vouches for a third party, and what level it may confer.
2. **Addressed offers.** A `for` field naming the recipient's HID, so a forwarded link is useless.
3. **Cancelling offers.** Revoking outstanding multi-use offers before they expire.
4. **Changing hashi.** Moving to a new hashi and telling existing contacts, without telling everyone.
5. **"Got a hashi?" hand-off.** For people with a hashi but no app, sending the offer to their provider to confirm, similar to Mastodon's remote follow.
6. **A slicker two-way exchange** than two separate offers.
7. **MCP binding** via OAuth 2.1.
8. **Recovery short of a reset** when an identity key is lost.
9. **Organisation-level policy** documents.
10. **Expressing an HID as a DID.**

## Next Steps

- Gather review from security and protocol practitioners.
- Build a reference HASHI server and app to test the specification end to end.
- Record the main design decisions so far as Architecture Decision Records.
