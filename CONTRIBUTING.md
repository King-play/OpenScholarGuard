# Contributing

Thanks for helping improve OpenScholarGuard. The project is designed to be useful to
researchers, conference organizers, and engineers building document agents.

## Local Setup

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src/openscholarguard
```

## Pull Request Standards

- Keep changes focused and testable.
- Add tests for new detectors, parser behavior, and sanitizer changes.
- Add or update benchmark cases when scanner behavior changes in a measurable way.
- Add audit/reporting tests when changing policy, suppression, SARIF, or JUnit behavior.
- Add ingestion tests when changing chunking, blocking, manifest, or JSONL behavior.
- Add API tests when changing HTTP routes, request schemas, or response serialization.
- Update the OpenAPI schema and client tests when changing service contracts.
- Add rule-pack validation and detector tests when changing custom rule behavior.
- Run `openscholarguard rules verify <pack> --require-tests` for contributed rule packs.
- Avoid adding heavy dependencies unless they unlock a clear capability.
- Include a short security rationale for new detector logic.
- Do not include real confidential submissions, private reviews, or proprietary papers.

## Detector Guidelines

Good detectors should:

- Produce evidence that a human can inspect.
- Return stable locations when possible.
- Prefer high precision for `high` and `critical` findings.
- Explain remediation clearly.
- Include tests with both positive and negative examples.

## Benchmark Guidelines

Benchmark cases should:

- Use synthetic content only.
- Include clear ground-truth labels.
- Name expected detectors explicitly.
- Avoid payloads that meaningfully enable harm outside defensive testing.
