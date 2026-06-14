"""Command-line interface for OpenScholarGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from openscholarguard import __version__
from openscholarguard.audit.policy import load_policy, write_default_policy
from openscholarguard.audit.reporters import (
    render_audit_report,
    write_audit_report,
)
from openscholarguard.audit.runner import audit_paths
from openscholarguard.benchmark.datasets import BUILTIN_DATASETS, get_builtin_dataset
from openscholarguard.benchmark.evaluator import evaluate_builtin_dataset, evaluate_manifest
from openscholarguard.benchmark.generator import generate_builtin_dataset
from openscholarguard.benchmark.leaderboard import (
    render_benchmark_markdown,
    render_benchmark_text,
    render_leaderboard_html,
    render_leaderboard_markdown,
    render_leaderboard_text,
    write_benchmark_report,
    write_leaderboard_report,
)
from openscholarguard.benchmark.publisher import publish_builtin_benchmark
from openscholarguard.benchmark.submissions import (
    build_leaderboard,
    create_leaderboard_entry,
    load_benchmark_evaluation,
    load_leaderboard_entries,
    write_leaderboard_entry,
)
from openscholarguard.demo import generate_demo
from openscholarguard.doctor import render_doctor_text, run_doctor
from openscholarguard.exceptions import OpenScholarGuardError
from openscholarguard.ingest.exporters import (
    render_jsonl,
    render_manifest,
    write_ingest_outputs,
)
from openscholarguard.ingest.models import IngestOptions
from openscholarguard.ingest.pipeline import ingest_path
from openscholarguard.llm.audit import run_llm_audit
from openscholarguard.llm.models import LLMAuditConfig, LLMAuditResult
from openscholarguard.models import ScanResult, Severity
from openscholarguard.profiles import PROFILES
from openscholarguard.reporting import render_text_report, write_report
from openscholarguard.rules.fingerprint import fingerprint_mismatch, rule_pack_sha256
from openscholarguard.rules.registry import load_rule_pack, load_rule_packs
from openscholarguard.rules.validation import validate_rule_pack
from openscholarguard.rules.verification import verify_rule_pack
from openscholarguard.sanitizer import sanitize_path
from openscholarguard.scanner import scan_path, should_fail
from openscholarguard.server import serve
from openscholarguard.server.openapi import openapi_schema


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except (OpenScholarGuardError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openscholarguard",
        description="Scan and sanitize scholarly documents for AI-review and RAG prompt-injection risks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_scan_parser(subparsers)
    _add_sanitize_parser(subparsers)
    _add_ingest_parser(subparsers)
    _add_audit_parser(subparsers)
    _add_benchmark_parser(subparsers)
    _add_demo_parser(subparsers)
    _add_rules_parser(subparsers)
    _add_init_policy_parser(subparsers)
    _add_openapi_parser(subparsers)
    _add_serve_parser(subparsers)
    _add_profiles_parser(subparsers)
    _add_doctor_parser(subparsers)
    return parser


def _add_scan_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("scan", help="scan a document")
    parser.add_argument("target", help="path to a PDF, Markdown, TeX, HTML, JSON, CSV, or text file")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="ai-review")
    parser.add_argument("--rule-pack", action="append", default=[], help="custom rule-pack JSON file")
    _add_llm_audit_arguments(parser)
    parser.add_argument(
        "--format",
        choices=["text", "json", "html", "md"],
        default="text",
        help="stdout/report format",
    )
    parser.add_argument("--output", "-o", help="write report to file")
    parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="exit with code 1 when at least this severity is found",
    )
    parser.set_defaults(func=_cmd_scan)


def _add_llm_audit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--llm-audit", action="store_true", help="run optional LLM review of scan findings")
    parser.add_argument("--llm-provider", choices=["openai"], default="openai", help="LLM audit provider")
    parser.add_argument("--llm-model", default="gpt-4.1-mini", help="LLM audit model")
    parser.add_argument("--llm-api-key-env", default="OPENAI_API_KEY", help="environment variable containing API key")
    parser.add_argument("--llm-base-url", default="https://api.openai.com/v1", help="LLM provider base URL")
    parser.add_argument("--llm-timeout", type=float, default=30.0, help="LLM request timeout in seconds")
    parser.add_argument("--llm-max-findings", type=int, default=12, help="maximum findings sent to the LLM")


def _add_sanitize_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("sanitize", help="remove high-risk model-facing content")
    parser.add_argument("target", help="path to a supported document")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="ai-review")
    parser.add_argument("--rule-pack", action="append", default=[], help="custom rule-pack JSON file")
    parser.add_argument("--output", "-o", help="write sanitized text to file")
    parser.add_argument(
        "--manifest",
        help="optional JSON file containing removed fragments and sanitizer metadata",
    )
    parser.set_defaults(func=_cmd_sanitize)


def _add_ingest_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("ingest", help="scan, sanitize, and chunk a document for RAG")
    parser.add_argument("target", help="path to a supported document")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="rag")
    parser.add_argument("--rule-pack", action="append", default=[], help="custom rule-pack JSON file")
    parser.add_argument(
        "--block-on",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help="block ingestion when at least this severity is found",
    )
    parser.add_argument(
        "--allow-risk",
        action="store_true",
        help="emit sanitized chunks even when the document reaches the block threshold",
    )
    parser.add_argument("--chunk-size", type=int, default=1200)
    parser.add_argument("--chunk-overlap", type=int, default=120)
    parser.add_argument("--min-chunk-chars", type=int, default=40)
    parser.add_argument("--no-findings", action="store_true", help="omit finding details from manifest output")
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "text", "manifest"],
        default="manifest",
        help="stdout format when --output-dir is not used",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        help="write clean markdown, chunks JSONL, and manifest files to this directory",
    )
    parser.set_defaults(func=_cmd_ingest)


def _add_profiles_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("profiles", help="list available scan profiles")
    parser.set_defaults(func=_cmd_profiles)


def _add_doctor_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("doctor", help="run environment and project health checks")
    parser.add_argument("--demo", action="store_true", help="also verify static demo generation")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.set_defaults(func=_cmd_doctor)


def _add_audit_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("audit", help="scan files and directories with CI-oriented output")
    parser.add_argument("targets", nargs="+", help="files or directories to audit")
    parser.add_argument("--policy", help="path to an audit policy JSON file")
    parser.add_argument("--rule-pack", action="append", default=[], help="custom rule-pack JSON file")
    parser.add_argument("--profile", choices=sorted(PROFILES), help="override policy scan profile")
    parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        help="override policy failure threshold",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html", "md", "sarif", "junit"],
        default="text",
        help="stdout/report format",
    )
    parser.add_argument("--output", "-o", help="write audit report to file")
    parser.set_defaults(func=_cmd_audit)


def _add_init_policy_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("init-policy", help="write a default audit policy JSON file")
    parser.add_argument(
        "--output",
        "-o",
        default=".openscholarguard.json",
        help="policy file path",
    )
    parser.set_defaults(func=_cmd_init_policy)


def _add_serve_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("serve", help="run the local OpenScholarGuard HTTP API")
    parser.add_argument("--host", default="127.0.0.1", help="bind host")
    parser.add_argument("--port", type=int, default=8765, help="bind port")
    parser.set_defaults(func=_cmd_serve)


def _add_openapi_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("openapi", help="print or write the OpenAPI schema")
    parser.add_argument("--output", "-o", help="write schema to this JSON file")
    parser.set_defaults(func=_cmd_openapi)


def _add_benchmark_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("benchmark", help="generate and evaluate benchmark suites")
    benchmark_subparsers = parser.add_subparsers(dest="benchmark_command", required=True)

    list_parser = benchmark_subparsers.add_parser("list", help="list built-in benchmark datasets")
    list_parser.set_defaults(func=_cmd_benchmark_list)

    generate_parser = benchmark_subparsers.add_parser("generate", help="generate benchmark documents")
    generate_parser.add_argument("--dataset", choices=sorted(BUILTIN_DATASETS), default="docpibench-mini")
    generate_parser.add_argument("--output-dir", "-o", required=True, help="directory for generated documents")
    generate_parser.add_argument("--extension", default=".md", help="generated document extension")
    generate_parser.add_argument(
        "--no-manifest",
        action="store_true",
        help="do not write manifest.json next to generated samples",
    )
    generate_parser.set_defaults(func=_cmd_benchmark_generate)

    evaluate_parser = benchmark_subparsers.add_parser("evaluate", help="evaluate scanner on a benchmark")
    source = evaluate_parser.add_mutually_exclusive_group()
    source.add_argument("--dataset", choices=sorted(BUILTIN_DATASETS), default="docpibench-mini")
    source.add_argument("--manifest", help="evaluate a generated benchmark manifest")
    evaluate_parser.add_argument("--profile", choices=sorted(PROFILES), default="ai-review")
    evaluate_parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
    )
    evaluate_parser.add_argument(
        "--work-dir",
        help="temporary directory used when evaluating a built-in dataset",
    )
    evaluate_parser.add_argument(
        "--format",
        choices=["text", "json", "html", "md"],
        default="text",
        help="stdout/report format",
    )
    evaluate_parser.add_argument("--output", "-o", help="write benchmark report to file")
    evaluate_parser.set_defaults(func=_cmd_benchmark_evaluate)

    submit_parser = benchmark_subparsers.add_parser(
        "submit",
        help="convert a benchmark evaluation JSON file into a leaderboard entry",
    )
    submit_parser.add_argument("evaluation", help="benchmark evaluation JSON produced by benchmark evaluate")
    submit_parser.add_argument("--system", required=True, help="system or model name")
    submit_parser.add_argument("--version", required=True, help="system version or run label")
    submit_parser.add_argument("--runner", default="openscholarguard", help="runner implementation")
    submit_parser.add_argument("--url", help="optional system, paper, or run URL")
    submit_parser.add_argument("--notes", help="short notes for the leaderboard")
    submit_parser.add_argument("--output", "-o", required=True, help="leaderboard entry JSON output")
    submit_parser.set_defaults(func=_cmd_benchmark_submit)

    leaderboard_parser = benchmark_subparsers.add_parser(
        "leaderboard",
        help="render a leaderboard from one or more submission entries",
    )
    leaderboard_parser.add_argument(
        "entries",
        nargs="+",
        help="leaderboard entry JSON files or directories containing entry JSON files",
    )
    leaderboard_parser.add_argument("--name", default="ScholarGuardBench", help="leaderboard title")
    leaderboard_parser.add_argument("--dataset", help="filter to this dataset")
    leaderboard_parser.add_argument("--dataset-version", help="filter to this dataset version")
    leaderboard_parser.add_argument(
        "--format",
        choices=["text", "json", "html", "md"],
        default="text",
        help="stdout/report format",
    )
    leaderboard_parser.add_argument("--output", "-o", help="write leaderboard report to file")
    leaderboard_parser.set_defaults(func=_cmd_benchmark_leaderboard)

    publish_parser = benchmark_subparsers.add_parser(
        "publish",
        help="create a shareable benchmark evaluation and leaderboard bundle",
    )
    publish_parser.add_argument("--dataset", choices=sorted(BUILTIN_DATASETS), default="docpibench-mini")
    publish_parser.add_argument("--profile", choices=sorted(PROFILES), default="ai-review")
    publish_parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
    )
    publish_parser.add_argument("--system", default="OpenScholarGuard", help="system or model name")
    publish_parser.add_argument("--version", default=__version__, help="system version or run label")
    publish_parser.add_argument("--runner", default="openscholarguard", help="runner implementation")
    publish_parser.add_argument("--url", default="https://github.com/King-play/OpenScholarGuard")
    publish_parser.add_argument("--notes", default="deterministic scanner baseline")
    publish_parser.add_argument("--leaderboard-name", default="ScholarGuardBench")
    publish_parser.add_argument("--output-dir", "-o", default="benchmark-publication")
    publish_parser.set_defaults(func=_cmd_benchmark_publish)


def _add_demo_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("demo", help="generate a shareable static demo bundle")
    parser.add_argument("--output-dir", "-o", default="demo-output", help="directory for demo artifacts")
    parser.add_argument("--sample", default="examples/injected_paper.md", help="sample document path")
    parser.add_argument("--rule-pack", default="examples/rule-pack.json", help="rule-pack JSON path")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="ai-review")
    parser.add_argument("--overwrite", action="store_true", help="overwrite an existing demo directory")
    parser.set_defaults(func=_cmd_demo)


def _add_rules_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("rules", help="validate and inspect custom rule packs")
    rules_subparsers = parser.add_subparsers(dest="rules_command", required=True)

    validate_parser = rules_subparsers.add_parser("validate", help="validate a rule-pack JSON file")
    validate_parser.add_argument("rule_pack")
    validate_parser.set_defaults(func=_cmd_rules_validate)

    verify_parser = rules_subparsers.add_parser("verify", help="validate fingerprints and embedded rule tests")
    verify_parser.add_argument("rule_pack")
    verify_parser.add_argument("--require-tests", action="store_true", help="fail when the pack has no tests")
    verify_parser.set_defaults(func=_cmd_rules_verify)

    fingerprint_parser = rules_subparsers.add_parser("fingerprint", help="print a rule-pack SHA-256 fingerprint")
    fingerprint_parser.add_argument("rule_pack")
    fingerprint_parser.set_defaults(func=_cmd_rules_fingerprint)

    list_parser = rules_subparsers.add_parser("list", help="list rules in a rule pack")
    list_parser.add_argument("rule_pack")
    list_parser.set_defaults(func=_cmd_rules_list)

    test_parser = rules_subparsers.add_parser("test", help="run a rule pack against text or a file")
    test_parser.add_argument("rule_pack")
    source = test_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--path")
    test_parser.set_defaults(func=_cmd_rules_test)


def _cmd_scan(args: argparse.Namespace) -> int:
    result = scan_path(args.target, profile=args.profile, rule_packs=load_rule_packs(args.rule_pack))
    audit = _maybe_run_llm_audit(result, args)

    if args.output:
        if audit is not None and args.format == "json":
            _write_json(args.output, _scan_payload(result, audit))
        else:
            write_report(result, args.output, fmt=args.format)
    elif args.format == "json":
        print(json.dumps(_scan_payload(result, audit), indent=2, sort_keys=True))
    elif args.format == "html":
        from openscholarguard.reporting import render_html_report

        print(render_html_report(result))
    elif args.format == "md":
        from openscholarguard.reporting import render_markdown_report

        print(render_markdown_report(result))
    else:
        print(render_text_report(result), end="")

    fail_on = args.fail_on or PROFILES[args.profile].fail_on
    return 1 if should_fail(result, fail_on) else 0


def _maybe_run_llm_audit(result: ScanResult, args: argparse.Namespace) -> Optional[LLMAuditResult]:
    if not getattr(args, "llm_audit", False):
        return None
    config = LLMAuditConfig(
        provider=args.llm_provider,
        model=args.llm_model,
        api_key_env=args.llm_api_key_env,
        base_url=args.llm_base_url,
        timeout_seconds=args.llm_timeout,
        max_findings=args.llm_max_findings,
    )
    return run_llm_audit(result, config=config)


def _scan_payload(result: ScanResult, audit: Optional[LLMAuditResult]) -> dict[str, object]:
    payload = result.to_dict()
    if audit is not None:
        payload["llm_audit"] = audit.to_dict()
    return payload


def _write_json(output: str, payload: dict[str, object]) -> None:
    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _cmd_sanitize(args: argparse.Namespace) -> int:
    result = sanitize_path(args.target, profile=args.profile, rule_packs=load_rule_packs(args.rule_pack))

    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result.text, encoding="utf-8")
    else:
        print(result.text, end="")

    if args.manifest:
        manifest_path = Path(args.manifest).expanduser()
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")

    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    options = IngestOptions(
        profile=args.profile,
        block_on=Severity(args.block_on),
        allow_risk=args.allow_risk,
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
        min_chunk_chars=args.min_chunk_chars,
        include_findings=not args.no_findings,
        rule_packs=tuple(load_rule_packs(args.rule_pack)),
    )
    result = ingest_path(args.target, options=options)

    if args.output_dir:
        outputs = write_ingest_outputs(result, args.output_dir)
        for name, path in outputs.items():
            print(f"{name}: {path}")
    elif args.format == "json":
        print(result.to_json())
    elif args.format == "jsonl":
        print(render_jsonl(result), end="")
    elif args.format == "text":
        print(result.sanitized_text, end="")
    else:
        print(render_manifest(result))

    return 1 if result.status.value == "blocked" else 0


def _cmd_audit(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    if args.profile or args.fail_on:
        from dataclasses import replace

        policy = replace(
            policy,
            profile=args.profile or policy.profile,
            fail_on=Severity(args.fail_on) if args.fail_on else policy.fail_on,
        )
    if args.rule_pack:
        from dataclasses import replace

        policy = replace(policy, rule_packs=tuple([*policy.rule_packs, *args.rule_pack]))
    result = audit_paths(args.targets, policy=policy)

    if args.output:
        write_audit_report(result, args.output, fmt=args.format)
    else:
        print(render_audit_report(result, fmt=args.format), end="")

    return 1 if result.has_failures() else 0


def _cmd_init_policy(args: argparse.Namespace) -> int:
    path = write_default_policy(args.output)
    print(f"Wrote audit policy: {path}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    serve(host=args.host, port=args.port)
    return 0


def _cmd_openapi(args: argparse.Namespace) -> int:
    payload = json.dumps(openapi_schema(), indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    artifacts = generate_demo(
        args.output_dir,
        sample_path=args.sample,
        rule_pack_path=args.rule_pack,
        profile=args.profile,
        overwrite=args.overwrite,
    )
    print(f"Demo written to: {artifacts.output_dir}")
    print(f"Open: {artifacts.index_html}")
    print(f"Scan JSON: {artifacts.scan_json}")
    return 0


def _cmd_rules_validate(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.rule_pack).expanduser().read_text(encoding="utf-8"))
    errors = validate_rule_pack(payload)
    mismatch = fingerprint_mismatch(payload)
    if mismatch is not None:
        errors.append(mismatch)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Rule pack is valid: {args.rule_pack}")
    return 0


def _cmd_rules_verify(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.rule_pack).expanduser().read_text(encoding="utf-8"))
    errors = validate_rule_pack(payload)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    rule_pack = load_rule_pack(args.rule_pack)
    verification = verify_rule_pack(
        rule_pack,
        raw_payload=payload,
        require_tests=args.require_tests,
    )
    print(f"Rule pack: {rule_pack.name} {rule_pack.version}")
    print(f"Fingerprint: {verification.fingerprint}")
    print(f"Tests: {len(verification.tests)}")
    for test in verification.tests:
        status = "PASS" if test.passed else "FAIL"
        rule_ids = ", ".join(test.matched_rule_ids) or "<none>"
        print(f"  {status} {test.name}: {test.finding_count} findings [{rule_ids}]")
        for error in test.errors:
            print(f"    error: {error}")
    for error in verification.errors:
        print(f"error: {error}", file=sys.stderr)
    return 0 if verification.passed else 1


def _cmd_rules_fingerprint(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.rule_pack).expanduser().read_text(encoding="utf-8"))
    errors = validate_rule_pack(payload)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"sha256:{rule_pack_sha256(payload)}")
    return 0


def _cmd_rules_list(args: argparse.Namespace) -> int:
    rule_pack = load_rule_pack(args.rule_pack)
    print(f"{rule_pack.name} {rule_pack.version}: {rule_pack.description}")
    print(f"  fingerprint: {rule_pack.fingerprint}")
    print(f"  tests: {len(rule_pack.tests)}")
    for rule in rule_pack.rules:
        print(f"  {rule.id}: {rule.severity.value} {rule.title}")
    return 0


def _cmd_rules_test(args: argparse.Namespace) -> int:
    from openscholarguard.document import load_text_document
    from openscholarguard.scanner import Scanner

    rule_pack = load_rule_pack(args.rule_pack)
    if args.text is not None:
        document = load_text_document(args.text, path="<rules-test>")
    else:
        from openscholarguard.document import load_document

        document = load_document(args.path)
    result = Scanner(profile="baseline", rule_packs=[rule_pack]).scan_document(document)
    print(render_text_report(result), end="")
    return 1 if result.findings else 0


def _cmd_benchmark_list(args: argparse.Namespace) -> int:
    for dataset in BUILTIN_DATASETS.values():
        print(f"{dataset.name} {dataset.version}: {dataset.description}")
        print(f"  cases: {len(dataset.cases)}")
        families = sorted({case.family.value for case in dataset.cases})
        print(f"  families: {', '.join(families)}")
    return 0


def _cmd_benchmark_generate(args: argparse.Namespace) -> int:
    samples = generate_builtin_dataset(
        args.dataset,
        args.output_dir,
        extension=args.extension,
        include_manifest=not args.no_manifest,
    )
    print(f"Generated {len(samples)} samples for {args.dataset} in {args.output_dir}")
    if not args.no_manifest:
        print(f"Manifest: {Path(args.output_dir).expanduser() / 'manifest.json'}")
    return 0


def _cmd_benchmark_evaluate(args: argparse.Namespace) -> int:
    fail_on = Severity(args.fail_on)
    if args.manifest:
        evaluation = evaluate_manifest(
            args.manifest,
            profile=args.profile,
            fail_on=fail_on,
        )
    else:
        dataset = get_builtin_dataset(args.dataset)
        evaluation = evaluate_builtin_dataset(
            dataset.name,
            profile=args.profile,
            fail_on=fail_on,
            work_dir=args.work_dir,
        )

    if args.output:
        write_benchmark_report(evaluation, args.output, fmt=args.format)
    elif args.format == "json":
        print(evaluation.to_json())
    elif args.format == "html":
        from openscholarguard.benchmark.leaderboard import render_benchmark_html

        print(render_benchmark_html(evaluation))
    elif args.format == "md":
        print(render_benchmark_markdown(evaluation))
    else:
        print(render_benchmark_text(evaluation), end="")

    return 0 if all(sample.passed for sample in evaluation.samples) else 1


def _cmd_benchmark_submit(args: argparse.Namespace) -> int:
    evaluation = load_benchmark_evaluation(args.evaluation)
    entry = create_leaderboard_entry(
        evaluation,
        system=args.system,
        version=args.version,
        runner=args.runner,
        url=args.url,
        notes=args.notes,
    )
    output = write_leaderboard_entry(entry, args.output)
    print(f"Leaderboard entry written to: {output}")
    return 0


def _cmd_benchmark_leaderboard(args: argparse.Namespace) -> int:
    leaderboard = build_leaderboard(
        load_leaderboard_entries(args.entries),
        name=args.name,
        dataset=args.dataset,
        dataset_version=args.dataset_version,
    )
    if args.output:
        write_leaderboard_report(leaderboard, args.output, fmt=args.format)
    elif args.format == "json":
        print(leaderboard.to_json())
    elif args.format == "html":
        print(render_leaderboard_html(leaderboard))
    elif args.format == "md":
        print(render_leaderboard_markdown(leaderboard))
    else:
        print(render_leaderboard_text(leaderboard), end="")
    return 0


def _cmd_benchmark_publish(args: argparse.Namespace) -> int:
    publication = publish_builtin_benchmark(
        args.output_dir,
        dataset=args.dataset,
        profile=args.profile,
        fail_on=Severity(args.fail_on),
        system=args.system,
        version=args.version,
        runner=args.runner,
        url=args.url,
        notes=args.notes,
        leaderboard_name=args.leaderboard_name,
    )
    print(f"Benchmark publication written to: {publication.output_dir}")
    print(f"Evaluation JSON: {publication.evaluation_json}")
    print(f"Leaderboard HTML: {publication.leaderboard_html}")
    print(f"Submission entry: {publication.entry_json}")
    return 0


def _cmd_profiles(args: argparse.Namespace) -> int:
    for profile in PROFILES.values():
        print(f"{profile.name}: {profile.description}")
        print(f"  fail_on: {profile.fail_on}")
        print(f"  detectors: {', '.join(sorted(profile.enabled_detectors))}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = run_doctor(include_demo=args.demo)
    if args.format == "json":
        print(report.to_json())
    else:
        print(render_doctor_text(report), end="")
    return 0 if report.status == "ok" else 1
