# ScholarGuardBench v0 Dataset Card

`scholarguardbench-v0` is a synthetic benchmark seed for document-borne prompt injection,
AI-review manipulation, RAG contamination, multimodal document ingestion, and agent
tool-boundary safety.

## Snapshot

| Field | Value |
| --- | --- |
| Dataset | `scholarguardbench-v0` |
| Version | `0.1.0` |
| Cases | 36 |
| Clean controls | 5 |
| Attack / integrity-risk cases | 31 |
| Source | Synthetic |
| Public split | `dev` |
| Default verifier | `detector-match` |
| Default expected actions | `allow`, `flag` |

## Task Design

Each case is treated as a small benchmark task. The generated manifest records:

- Stable `task_id`.
- Attack family and human-readable title.
- Ground-truth malicious label.
- Expected detector IDs.
- Minimum expected severity.
- Target workflow.
- Payload visibility.
- Document modality.
- Difficulty.
- Verifier contract.
- Expected action.

This keeps the dataset compatible with scanner baselines today and model-facing review
evaluations later. A model-evaluation run can reuse the same task IDs while replacing the
deterministic verifier with a judge over model responses.

## Coverage

The v0 seed covers:

- Clean scholarly controls.
- Direct prompt-instruction override.
- Peer-review outcome manipulation.
- RAG context and prompt exfiltration.
- RAG retrieval contamination.
- Base64 and hex encoded payloads.
- Invisible Unicode and homoglyph obfuscation.
- Hidden HTML/CSS and LaTeX content.
- Metadata, OCR-layer, and image-text injection.
- Multilingual review pressure.
- Citation manipulation and fake-reference generation.
- Role-play authority hijacking.
- AI slop and placeholder evidence.
- Tool-based secret exfiltration.

## Intended Use

Use this dataset to:

- Regression-test OpenScholarGuard detectors.
- Compare document safety scanners under a shared manifest.
- Generate public benchmark reports and leaderboard entries.
- Produce model-facing prompts for AI-review robustness experiments.
- Build demos that show concrete, auditable document attack examples.

## Out Of Scope

This dataset is not a real-paper corpus and does not contain private submissions, reviews,
or reviewer data. It is not intended to estimate real-world prevalence. It is a controlled
seed benchmark for reproducible engineering and early research comparison.

## Expansion Plan

The next dataset milestones are:

1. Add `test` and `challenge` splits with held-out payload variants.
2. Add rendered PDF fixtures for visual/text mismatch, white text, transparent spans,
   metadata injection, OCR-layer text, and image-embedded text.
3. Add model-response JSONL runs and dated public leaderboards.
4. Add oracle solution notes for each task.
5. Add external baseline entries for other scanners, prompt firewalls, and RAG guards.

