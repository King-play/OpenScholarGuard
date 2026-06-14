"""Generate a complete static project site bundle."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from openscholarguard.benchmark.publisher import BenchmarkPublication, publish_builtin_benchmark
from openscholarguard.demo import DemoArtifacts, generate_demo
from openscholarguard.site.html import render_site_index


@dataclass(frozen=True)
class SiteArtifacts:
    """Paths written by the static site generator."""

    output_dir: Path
    index_html: Path
    demo_dir: Path
    benchmark_dir: Path
    demo: DemoArtifacts
    benchmark: BenchmarkPublication

    def to_dict(self) -> dict[str, str]:
        return {
            "output_dir": str(self.output_dir),
            "index_html": str(self.index_html),
            "demo_dir": str(self.demo_dir),
            "benchmark_dir": str(self.benchmark_dir),
            "demo_index_html": str(self.demo.index_html),
            "benchmark_leaderboard_html": str(self.benchmark.leaderboard_html),
        }


def generate_site(
    output_dir: Union[str, Path],
    *,
    overwrite: bool = False,
) -> SiteArtifacts:
    """Generate a project site with demo and benchmark sections."""

    output_path = Path(output_dir).expanduser()
    if output_path.exists() and any(output_path.iterdir()) and not overwrite:
        raise ValueError(f"Site output directory already exists and is not empty: {output_path}")
    if output_path.exists() and overwrite:
        shutil.rmtree(output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    demo_dir = output_path / "demo"
    benchmark_dir = output_path / "benchmark"
    demo = generate_demo(demo_dir, overwrite=True)
    benchmark = publish_builtin_benchmark(benchmark_dir)
    index_html = output_path / "index.html"
    index_html.write_text(render_site_index(demo=demo, benchmark=benchmark), encoding="utf-8")

    return SiteArtifacts(
        output_dir=output_path,
        index_html=index_html,
        demo_dir=demo_dir,
        benchmark_dir=benchmark_dir,
        demo=demo,
        benchmark=benchmark,
    )
