#!/usr/bin/env python3
"""Download the Innoc2Scam benchmark dataset from Hugging Face."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

try:
    from huggingface_hub import snapshot_download
except ImportError as exc:
    raise SystemExit(
        "Missing dependency 'huggingface_hub'. Install it with "
        "'python3 -m pip install -r requirements.txt' before running this script."
    ) from exc


DATASET_ID = "anonymous-author-32423/Innoc2Scam-bench"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download the Innoc2Scam benchmark dataset from Hugging Face."
    )
    parser.add_argument(
        "--output-dir",
        default="data/innoc2scam",
        help="Destination directory for the downloaded dataset (default: data/innoc2scam).",
    )
    parser.add_argument(
        "--cache-dir",
        help="Optional Hugging Face cache directory to reuse cached files.",
    )
    parser.add_argument(
        "--revision",
        help=(
            "Specific dataset revision (e.g., a git commit hash or tag) if you need a "
            "non-default version."
        ),
    )
    parser.add_argument(
        "--extract-prompts",
        action="store_true",
        help=(
            "Extract the 'prompts' array from Innoc2Scam-bench.json into prompts.jsonl. "
            "This avoids schema mismatches in downstream tooling."
        ),
    )
    return parser.parse_args()


def ensure_environment(args: argparse.Namespace) -> None:
    """Propagate optional cache directory settings to the Hugging Face tooling."""
    if args.cache_dir:
        os.environ["HF_DATASETS_CACHE"] = args.cache_dir


def snapshot_dataset(args: argparse.Namespace, output_path: Path) -> Path:
    """Download the dataset repository snapshot into the requested directory."""
    download_kwargs: dict[str, Any] = {
        "repo_id": DATASET_ID,
        "repo_type": "dataset",
        "local_dir": output_path.as_posix(),
    }
    if args.cache_dir:
        download_kwargs["cache_dir"] = args.cache_dir
    if args.revision:
        download_kwargs["revision"] = args.revision

    snapshot_location = snapshot_download(**download_kwargs)
    snapshot_path = Path(snapshot_location)
    print(f"Dataset snapshot downloaded to {snapshot_path}")
    return snapshot_path


def extract_prompts(snapshot_path: Path) -> None:
    """Write the prompts array from the root JSON file to newline-delimited JSON."""
    source_file = snapshot_path / "Innoc2Scam-bench.json"
    if not source_file.exists():
        print("No Innoc2Scam-bench.json found in snapshot; skipping prompt extraction.")
        return

    with source_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    prompts = data.get("prompts")
    if not isinstance(prompts, list):
        print("The 'prompts' field is missing or not a list; skipping prompt extraction.")
        return

    output_file = snapshot_path / "prompts.jsonl"
    with output_file.open("w", encoding="utf-8") as f:
        for item in prompts:
            json.dump(item, f)
            f.write("\n")

    print(f"Extracted {len(prompts)} prompts to {output_file}")


def download_dataset(args: argparse.Namespace) -> None:
    """Coordinate the download workflow and optional prompt extraction."""
    ensure_environment(args)
    output_path = Path(args.output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    snapshot_path = snapshot_dataset(args, output_path)

    if args.extract_prompts:
        extract_prompts(snapshot_path)

    print("Download completed successfully.")


def main() -> None:
    args = parse_args()
    download_dataset(args)


if __name__ == "__main__":
    main()
