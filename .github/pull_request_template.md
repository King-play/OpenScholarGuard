## Summary

What changed?

## Type

- [ ] Scanner or detector behavior
- [ ] Sanitizer or ingestion behavior
- [ ] Rule-pack or benchmark content
- [ ] API, CLI, or client contract
- [ ] Documentation, demo, or repository automation

## Security Rationale

Why is this change safe and useful for document-agent security?

## Tests

```bash
python -m pytest
python -m ruff check .
python -m mypy src/openscholarguard
python -m openscholarguard doctor --demo
```

## Data Handling

- [ ] This PR does not include confidential submissions, private reviews, or proprietary papers.
- [ ] Synthetic examples are clearly marked as synthetic.
- [ ] New rule packs include positive and negative embedded tests.

## Screenshots or Demo

Add a screenshot, `demo-output/index.html` capture, or CLI output when the change affects user-facing behavior.
