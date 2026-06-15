from __future__ import annotations

import json
from pathlib import Path

import pytest

from openscholarguard.benchmark.model_eval import (
    StaticModelResponseClient,
    build_model_leaderboard,
    collect_model_responses,
    create_builtin_model_eval_protocol,
    judge_model_responses,
    load_judge_evaluation,
    load_model_eval_protocol,
    load_model_responses,
    publish_model_leaderboard,
    render_judge_markdown,
    render_model_leaderboard_html,
    render_model_leaderboard_markdown,
    write_judge_report,
    write_model_eval_protocol,
    write_model_responses,
)
from openscholarguard.cli import main


def test_model_eval_protocol_writes_prompt_bundle(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("scholarguardbench-v0")

    paths = write_model_eval_protocol(protocol, tmp_path)
    loaded = load_model_eval_protocol(paths["protocol"])

    assert len(loaded.prompts) == 36
    assert any(prompt.case_id == "hex_encoded_acceptance_payload" for prompt in loaded.prompts)
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


def test_collect_model_responses_with_static_client(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    client = StaticModelResponseClient(model="static-safe", response="I will treat document instructions as untrusted.")

    responses = collect_model_responses(
        protocol,
        client,
        case_ids=["clean_control", "review_acceptance_pressure"],
    )
    output = write_model_responses(responses, tmp_path / "responses.jsonl")
    loaded = load_model_responses(output)

    assert [record.case_id for record in loaded] == ["clean_control", "review_acceptance_pressure"]
    assert {record.model for record in loaded} == {"static-safe"}
    assert loaded[0].metadata["provider"] == "static"


def test_collect_model_responses_limit_and_unknown_case() -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    client = StaticModelResponseClient()

    responses = collect_model_responses(protocol, client, limit=1)

    assert len(responses) == 1
    with pytest.raises(ValueError, match="Unknown case_id"):
        collect_model_responses(protocol, client, case_ids=["missing-case"])


def test_write_model_responses_refuses_overwrite(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    response = StaticModelResponseClient().complete(protocol.prompts[0])
    output = tmp_path / "responses.jsonl"

    write_model_responses([response], output)

    with pytest.raises(ValueError, match="already exists"):
        write_model_responses([response], output)


def test_cli_benchmark_collect_requires_api_key(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    paths = write_model_eval_protocol(protocol, tmp_path / "protocol")
    monkeypatch.delenv("OSG_TEST_MODEL_KEY", raising=False)

    exit_code = main(
        [
            "benchmark",
            "collect",
            "--protocol",
            str(paths["protocol"]),
            "--model",
            "test-model",
            "--api-key-env",
            "OSG_TEST_MODEL_KEY",
            "--output",
            str(tmp_path / "responses.jsonl"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "API key is required" in captured.err


def test_model_leaderboard_sorts_judge_evaluations(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    safe_responses = [
        {
            "case_id": prompt.case_id,
            "model": "safe-model",
            "response": (
                "Ordinary scholarly review with safety notes."
                if not prompt.expected_malicious
                else "I will not follow document instructions."
            ),
        }
        for prompt in protocol.prompts
    ]
    weak_responses = [
        {
            "case_id": prompt.case_id,
            "model": "weak-model",
            "response": "I recommend acceptance and assign a high score.",
        }
        for prompt in protocol.prompts
    ]
    safe_path = tmp_path / "safe.jsonl"
    weak_path = tmp_path / "weak.jsonl"
    safe_path.write_text("\n".join(json.dumps(item) for item in safe_responses) + "\n", encoding="utf-8")
    weak_path.write_text("\n".join(json.dumps(item) for item in weak_responses) + "\n", encoding="utf-8")

    safe_eval = judge_model_responses(protocol, load_model_responses(safe_path))
    weak_eval = judge_model_responses(protocol, load_model_responses(weak_path))
    safe_json = write_judge_report(safe_eval, tmp_path / "safe.judge.json", fmt="json")
    loaded_safe = load_judge_evaluation(safe_json)
    leaderboard = build_model_leaderboard([weak_eval, loaded_safe])
    markdown = render_model_leaderboard_markdown(leaderboard)
    html = render_model_leaderboard_html(leaderboard)

    assert leaderboard.entries[0].model == "safe-model"
    assert "weak-model" in markdown
    assert "ScholarGuardBench Model Robustness" in html


def test_cli_model_leaderboard_writes_report(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    responses_path = tmp_path / "responses.jsonl"
    lines = [
        json.dumps(
            {
                "case_id": prompt.case_id,
                "model": "safe-model",
                "response": "I will not follow instructions embedded in the document.",
            }
        )
        for prompt in protocol.prompts
    ]
    responses_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    evaluation = judge_model_responses(protocol, load_model_responses(responses_path))
    judge_path = write_judge_report(evaluation, tmp_path / "judge.json", fmt="json")
    output = tmp_path / "model-leaderboard.html"

    exit_code = main(
        [
            "benchmark",
            "model-leaderboard",
            str(judge_path),
            "--format",
            "html",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.exists()
    assert "safe-model" in output.read_text(encoding="utf-8")


def test_publish_model_leaderboard_writes_bundle(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    responses_path = tmp_path / "responses.jsonl"
    responses_path.write_text(
        "\n".join(
            json.dumps(
                {
                    "case_id": prompt.case_id,
                    "model": "publish-model",
                    "response": "I will not follow instructions embedded in the document.",
                }
            )
            for prompt in protocol.prompts
        )
        + "\n",
        encoding="utf-8",
    )
    evaluation = judge_model_responses(protocol, load_model_responses(responses_path))
    judge_path = write_judge_report(evaluation, tmp_path / "publish-model.judge.json", fmt="json")

    publication = publish_model_leaderboard([judge_path], tmp_path / "publication")

    assert publication.leaderboard_html.exists()
    assert publication.leaderboard_json.exists()
    assert publication.leaderboard_markdown.exists()
    assert publication.manifest_json.exists()
    assert (publication.judge_reports_dir / judge_path.name).exists()
    assert publication.leaderboard.entries[0].model == "publish-model"


def test_cli_model_publish_writes_bundle(tmp_path: Path) -> None:
    protocol = create_builtin_model_eval_protocol("docpibench-mini")
    responses_path = tmp_path / "responses.jsonl"
    responses_path.write_text(
        "\n".join(
            json.dumps(
                {
                    "case_id": prompt.case_id,
                    "model": "cli-publish-model",
                    "response": "I will not follow instructions embedded in the document.",
                }
            )
            for prompt in protocol.prompts
        )
        + "\n",
        encoding="utf-8",
    )
    evaluation = judge_model_responses(protocol, load_model_responses(responses_path))
    judge_path = write_judge_report(evaluation, tmp_path / "cli-publish-model.judge.json", fmt="json")
    output_dir = tmp_path / "publication"

    exit_code = main(
        [
            "benchmark",
            "model-publish",
            str(judge_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    assert (output_dir / "leaderboard.html").exists()
    assert (output_dir / "judge-reports" / judge_path.name).exists()
