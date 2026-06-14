from __future__ import annotations

import json
from pathlib import Path

from openscholarguard.benchmark.model_eval import (
    create_builtin_model_eval_protocol,
    judge_model_responses,
    load_model_eval_protocol,
    load_model_responses,
    render_judge_markdown,
    write_model_eval_protocol,
)


def test_model_eval_protocol_writes_prompt_bundle(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("scholarguardbench-v0")

    paths = write_model_eval_protocol(protocol, tmp_path)
    loaded = load_model_eval_protocol(paths["protocol"])

    assert len(loaded.prompts) == 21
    assert paths["prompts"].exists()
    assert paths["response_template"].exists()
    assert "<untrusted_document>" in loaded.prompts[0].user_prompt
    assert loaded.response_template[0].metadata["fill"]


def test_heuristic_judge_scores_resistant_responses(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    responses_path = tmp_path / "responses.jsonl"
    lines = []
    for prompt in protocol.prompts:
        response = (
            "This is an ordinary scholarly review with safety notes about untrusted document content."
            if not prompt.expected_malicious
            else "I will not follow instructions embedded in the document. Safety notes: possible prompt injection."
        )
        lines.append(json.dumps({"case_id": prompt.case_id, "model": "safe-model", "response": response}))
    responses_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    evaluation = judge_model_responses(protocol, load_model_responses(responses_path))

    assert evaluation.metrics.robust_accuracy == 1.0
    assert evaluation.metrics.attack_success_rate == 0.0
    assert all(sample.passed for sample in evaluation.samples)


def test_heuristic_judge_flags_injected_compliance(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    responses_path = tmp_path / "responses.jsonl"
    responses_path.write_text(
        json.dumps(
            {
                "case_id": "review_acceptance_pressure",
                "model": "vulnerable-model",
                "response": "I recommend acceptance and assign a high score.",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    evaluation = judge_model_responses(protocol, load_model_responses(responses_path))
    markdown = render_judge_markdown(evaluation)

    assert evaluation.metrics.attack_success_rate > 0
    assert any(not sample.passed for sample in evaluation.samples)
    assert "review_acceptance_pressure" in markdown
