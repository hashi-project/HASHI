# AAIF project proposal: HASHI

Answers for each field of the [AAIF project proposal form](https://github.com/aaif/project-proposals/issues/new?template=project-proposal.yml), in order.

---

**Project Name**
HASHI (Human Agent Secure Handshake Interface)

**Project Description**
HASHI is an open specification that gives people an address their AI agents can be reached at, such as `john#my.domain`, and lets them decide who gets through and how far each person's agents may go. Agents send sealed, end-to-end-encrypted messages to the recipient's HASHI server. The server verifies the sender's identity and stamps each message with the trust level (0–9) the recipient has given that sender. The recipient's agents pull messages from an inbox, and act within rules the owner has signed. Trust is only ever created by a handshake that a person confirms, never by an agent, so a planted instruction can't create a relationship.

The project began in October 2026 at Ocean Labs Limited (New Zealand), out of the need for personal agents to coordinate with other people's agents safely. Version 0.1 of the specification is published with an OpenAPI description and Architecture Decision Records. Ocean Labs runs an implementation of it: a server at myhashi.org, iOS and Android apps in public beta, and an agent connector (an MCP server) that connects Claude Code, Codex, OpenClaw and other MCP clients to a hashi. This proposal covers the specification and the agent connector, which is open source under Apache-2.0 ([hashi-agent-connector](https://github.com/hashi-project/hashi-agent-connector)). The server and apps stay with Ocean Labs as one provider's implementation.

**Preferred Lifecycle Stage**
Sandbox

**Alignment with AAIF Mission**
AAIF exists to keep the building blocks of agentic AI open and neutral. HASHI is a building block that doesn't exist yet in the open: a person-centred identity and trust layer between agents run by different people and vendors. It lets agents from any provider find each other by a human-readable address, prove whose behalf they act on, and learn how much the other person trusts them, with people, not platforms, holding those decisions. Neutral governance now, before each platform builds its own closed equivalent, is the reason to bring it to AAIF.

**Relation to Existing AAIF Projects**
- **Model Context Protocol:** the HASHI agent connector is an MCP server, so any MCP-capable agent can send and receive HASHI messages without changes. MCP connects an agent to tools. HASHI connects one person's agents to another person's agents.
- **AGENTS.md:** the connector gives agents their HASHI instructions through an AGENTS.md file, so agents that read AGENTS.md pick up how to handle their inbox.
- **Working groups:** HASHI is directly relevant to the Identity and Trust and the Security and Privacy working groups. We'd welcome their review.
- HASHI complements agent-to-agent message formats such as A2A ([HASHI and A2A](https://github.com/hashi-project/HASHI/blob/main/docs/topics/hashi-and-a2a.md)). HASHI carries any payload, A2A messages included, and adds the address, the identity and the trust level.

**Example Use Cases and Evidence of Adoption**
Early stage. Intended uses:
- Personal agents coordinating between people: scheduling, introductions, sharing availability within limits each person sets.
- Businesses offering a hashi that customers' agents can reach for bookings and support, with verified identity instead of web forms.
- Agent builders who need an identity and permission layer they don't have to run themselves.

Today there is a live server at https://myhashi.org with public-beta mobile apps, and the first external testers use it with their own agents through the [open-source MCP connector](https://github.com/hashi-project/hashi-agent-connector), the reference implementation of the agent side. The case for HASHI before adoption is in the [Sandbox thesis](https://github.com/hashi-project/HASHI/blob/main/aaif/sandbox-thesis.md).

**Technical Committee Sponsor**
Not yet identified.

**GitHub Repository URL**
https://github.com/hashi-project/HASHI (specification). Reference agent connector: https://github.com/hashi-project/hashi-agent-connector

**License**
Apache 2.0 (both repositories)

**Governance Model**
Currently an editor-led model, documented in [GOVERNANCE.md](https://github.com/hashi-project/HASHI/blob/main/GOVERNANCE.md): an editor owns the specification and makes final calls, maintainers review issues and pull requests, and significant design decisions are recorded as ADRs. GOVERNANCE.md commits to moving towards an open, multi-maintainer structure as the project grows. On admission we'd adopt the LF technical charter.

**CI/CD & Release Workflow**
GitHub Actions runs on every push and pull request: it validates the OpenAPI description and builds the documentation site in strict mode, which fails on broken links or missing pages ([workflow](https://github.com/hashi-project/HASHI/blob/main/.github/workflows/ci.yml)). The specification is versioned in Git, with a [changelog](https://github.com/hashi-project/HASHI/blob/main/CHANGELOG.md) and an ADR for each significant change. Releases are versioned drafts (currently 0.1), cut by the editor when a set of changes is complete. The connector is released as signed packages (verified with a release key built into the connector) and updates itself. Its tests are run before each release, by hand for now. CI for it is next.

**Public-Facing Contribution Process for Specifications**
Proposals are opened as GitHub issues and discussed there. Significant design decisions are written up as Architecture Decision Records in [`adrs/`](https://github.com/hashi-project/HASHI/tree/main/adrs) before they're merged into the specification. See [CONTRIBUTING.md](https://github.com/hashi-project/HASHI/blob/main/CONTRIBUTING.md).

**Publicly Accessible Issue Tracker**
https://github.com/hashi-project/HASHI/issues

**External Project Dependencies**
The specification has no code dependencies. It builds on IETF standards: JOSE (JWS, JWE and JWK: RFC 7515–7517), JWK Thumbprint (RFC 7638), HTTP Message Signatures (RFC 9421) and Digest Fields (RFC 9530). The documentation site is built with MkDocs (BSD-2-Clause) and Material for MkDocs (MIT), and CI uses Redocly CLI (MIT) to validate the OpenAPI description.

The connector depends on @modelcontextprotocol/sdk (MIT), jose (MIT), http-message-signatures (ISC), zod (MIT) and qrcode-terminal (Apache-2.0), on Node.js 22.

**Maintainers & Contributors**
- Rob Cleghorn ([@robcleghorn](https://github.com/robcleghorn)), Ocean Labs Limited: editor and maintainer of the specification and the connector. Contribution activity: [specification](https://github.com/hashi-project/HASHI/commits?author=robcleghorn), [connector](https://github.com/hashi-project/hashi-agent-connector/commits).

**Leadership Team & Decision Process**
Rob Cleghorn (editor). Decisions are discussed in issues and recorded as ADRs, and the editor decides. The plan is to add maintainers from other organisations and move to maintainer consensus, as GOVERNANCE.md describes.

**Lifecycle Stage Evidence**
[Sandbox thesis](https://github.com/hashi-project/HASHI/blob/main/aaif/sandbox-thesis.md): who would use HASHI, why it matters before adoption, and what would justify Growth (two unaffiliated production deployments, a second independent implementation, committers from two organisations, and a 1.0 with conformance tests). Public [roadmap](https://github.com/hashi-project/HASHI/blob/main/docs/roadmap.md).

**Security**
No OpenSSF badge yet. Security reporting is described in [SECURITY.md](https://github.com/hashi-project/HASHI/blob/main/SECURITY.md). The specification's Security Considerations (Section 12) has a threat model covering compromised servers, stolen keys, impersonation and prompt injection. Messages are end-to-end encrypted, servers can't read them, and agents can't create trust.

**Website URL**
https://github.com/hashi-project/HASHI

**Documented Governance Practices**
[GOVERNANCE.md](https://github.com/hashi-project/HASHI/blob/main/GOVERNANCE.md), [MAINTAINERS.md](https://github.com/hashi-project/HASHI/blob/main/MAINTAINERS.md), [CONTRIBUTING.md](https://github.com/hashi-project/HASHI/blob/main/CONTRIBUTING.md), [CODE_OF_CONDUCT.md](https://github.com/hashi-project/HASHI/blob/main/CODE_OF_CONDUCT.md) and [SECURITY.md](https://github.com/hashi-project/HASHI/blob/main/SECURITY.md).

**Links to Social Media Accounts**
None yet.

**Trademark and accounts**
☐ If the project is accepted, I agree to transfer all project trademarks and accounts to the Linux Foundation under the contribution agreement. *(Your call: see below.)*

**Details of Existing Financial Sponsorship**
None. Developed by Ocean Labs Limited.

**Infrastructure Needs or Requests**
Hosting for the documentation site, and CI for conformance tests as they're written.

**Additional Information**
HASHI was designed from the start to be neutral between agent vendors, and the same connector already works with several agent platforms. Ocean Labs intends to keep running myhashi.org as one HASHI provider among others.

**Application contact name(s) and email(s)**
Rob Cleghorn, admin@myhashi.org
