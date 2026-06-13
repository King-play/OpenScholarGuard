"""Benchmark utilities for document prompt-injection robustness."""

from __future__ import annotations

from openscholarguard.benchmark.datasets import BUILTIN_DATASETS, get_builtin_dataset
from openscholarguard.benchmark.evaluator import evaluate_benchmark
from openscholarguard.benchmark.generator import generate_documents
from openscholarguard.benchmark.models import (
    BenchmarkCase,
    BenchmarkDataset,
    BenchmarkEvaluation,
    BenchmarkMetrics,
    BenchmarkSampleResult,
)

__all__ = [
    "BUILTIN_DATASETS",
    "BenchmarkCase",
    "BenchmarkDataset",
    "BenchmarkEvaluation",
    "BenchmarkMetrics",
    "BenchmarkSampleResult",
    "evaluate_benchmark",
    "generate_documents",
    "get_builtin_dataset",
]
