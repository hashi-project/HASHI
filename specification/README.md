# Specification Artefacts

| File | Description |
|------|-------------|
| [`hashi-openapi.yaml`](hashi-openapi.yaml) | OpenAPI 3.1 description of the HASHI server's HTTP API: resolve, redeem, send, and the inbox (list, claim, release, delete and wake-up channels). |

The normative text is [`docs/specification.md`](../docs/specification.md). Where the two disagree, the specification wins, and the mismatch is a bug worth reporting.

## Validating

```bash
pip install openapi-spec-validator
openapi-spec-validator specification/hashi-openapi.yaml
```
