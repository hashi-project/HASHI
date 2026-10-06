# Contributing to HASHI

Thanks for your interest in HASHI. The specification is at an early draft stage, so feedback on the design is the most useful contribution right now.

## Ways to Contribute

- **Ask a question or report a problem** by opening an issue.
- **Propose a change** to the specification by opening an issue first, then a pull request once the approach is agreed.
- **Record a significant design decision** as an Architecture Decision Record in [`adrs/`](adrs/), using the [template](adrs/adr-template.md).

## Pull Requests

- Keep each pull request focused on one change.
- If you change the HTTP API, update both [`docs/specification.md`](docs/specification.md) and [`specification/hashi-openapi.yaml`](specification/hashi-openapi.yaml) so they stay in step.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages, for example `feat(spec): add addressed offers` or `fix(openapi): require from on knock`.
- Requirement keywords (**MUST**, **SHOULD**, **MAY** and so on) are written in bold capitals, as described in the specification.

## Versioning

The specification version is set by the editor. Please don't change it in a pull request.

## Code of Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
