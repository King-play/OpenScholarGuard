"""Capture reproducible README and demo media assets.

The script intentionally depends only on Python's standard library and a local Chromium or
Chrome executable. It generates PNG screenshots and ordered frame images that can be turned
into GIF/MP4 assets with ImageMagick or ffmpeg when those tools are available.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from openscholarguard.site import generate_site

DEFAULT_WINDOWS_CHROME = Path("C:/Program Files/Google/Chrome/Application/chrome.exe")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser()
    frames_dir = output_dir / "demo-frames"
    site_dir = Path(args.site_dir).expanduser()
    chrome = _resolve_chrome(args.chrome)

    output_dir.mkdir(parents=True, exist_ok=True)
    if frames_dir.exists():
        shutil.rmtree(frames_dir)
    frames_dir.mkdir(parents=True)

    generate_site(site_dir, overwrite=True)

    captures = [
        Capture("site", site_dir / "index.html", output_dir / "site-preview.png", args.width, args.height),
        Capture("demo", site_dir / "demo" / "index.html", output_dir / "demo-preview.png", args.width, args.height),
        Capture(
            "leaderboard",
            site_dir / "benchmark" / "leaderboard.html",
            output_dir / "leaderboard-preview.png",
            args.width,
            args.height,
        ),
    ]
    for capture in captures:
        _capture(chrome, capture)

    frame_specs = [
        ("001-site", site_dir / "index.html", ""),
        ("002-demo-hero", site_dir / "demo" / "index.html", ""),
        ("003-demo-findings", site_dir / "demo" / "index.html", "findings"),
        ("004-demo-ingestion", site_dir / "demo" / "index.html", "ingestion"),
        ("005-leaderboard", site_dir / "benchmark" / "leaderboard.html", ""),
    ]
    for name, html_path, fragment in frame_specs:
        _capture(
            chrome,
            Capture(
                name,
                html_path,
                frames_dir / f"{name}.png",
                args.width,
                args.height,
                fragment=fragment,
            ),
        )

    print(f"Captured README preview: {output_dir / 'demo-preview.png'}")
    print(f"Captured site preview: {output_dir / 'site-preview.png'}")
    print(f"Captured frames: {frames_dir}")
    return 0


class Capture:
    def __init__(
        self,
        name: str,
        html_path: Path,
        output_path: Path,
        width: int,
        height: int,
        *,
        fragment: str = "",
    ) -> None:
        self.name = name
        self.html_path = html_path
        self.output_path = output_path
        self.width = width
        self.height = height
        self.fragment = fragment


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture OpenScholarGuard demo media assets.")
    parser.add_argument("--output-dir", default="docs/assets", help="directory for screenshots and frames")
    parser.add_argument("--site-dir", default="site-output", help="temporary static site output directory")
    parser.add_argument("--chrome", help="path to Chrome or Chromium executable")
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=1040)
    return parser


def _resolve_chrome(chrome: str | None) -> Path:
    if chrome:
        candidate = Path(chrome).expanduser()
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"Chrome executable not found: {candidate}")
    discovered = shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("chromium")
    if discovered:
        return Path(discovered)
    if DEFAULT_WINDOWS_CHROME.exists():
        return DEFAULT_WINDOWS_CHROME
    raise FileNotFoundError("Could not find Chrome/Chromium. Pass --chrome <path>.")


def _capture(chrome: Path, capture: Capture) -> None:
    capture.output_path.parent.mkdir(parents=True, exist_ok=True)
    url = _capture_url(capture)
    args = [
        str(chrome),
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--virtual-time-budget=3000",
        f"--window-size={capture.width},{capture.height}",
        f"--screenshot={capture.output_path.resolve()}",
    ]
    args.append(url)
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    if completed.returncode != 0 or not capture.output_path.exists():
        message = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"Failed to capture {capture.name}: {message}")


def _capture_url(capture: Capture) -> str:
    html_uri = capture.html_path.resolve().as_uri()
    if not capture.fragment:
        return html_uri
    return f"{html_uri}#{capture.fragment}"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
