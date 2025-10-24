# Innoc2Scam Bench Usage Guide

Quick use:

```bash
python3 -m pip install -r requirements.txt
python3 download_innoc2scam.py --output-dir data/innoc2scam
```

Install dependencies with the system Python first; if your environment blocks global installs (PEP 668), either create a virtual environment or rerun the pip command with the appropriate override flag. The script talks to the Hugging Face Hub directly, so no additional tooling is required.

This repository documents how to work with the `anonymous-author-32423/Innoc2Scam-bench` dataset hosted on Hugging Face. Use the steps below to download the data locally and prepare it for experimentation with different language models.

## Prerequisites

- Python 3.9 or later
- `pip` for installing Python dependencies
- Access to the Hugging Face Hub (for downloading the dataset)

Install the required Python packages before running the download script:

```bash
python3 -m pip install -r requirements.txt
```

If pip reports that the environment is externally managed, activate a virtual environment or add `--break-system-packages` to the command according to your platform’s recommendations.

## Step 1: Download the dataset

The `download_innoc2scam.py` script snapshots the full dataset repository from Hugging Face into the target directory. Add `--extract-prompts` if you also want a flattened `prompts.jsonl` file extracted from `Innoc2Scam-bench.json`.

```bash
python3 download_innoc2scam.py --output-dir data/innoc2scam
```

Optional arguments:

- `--cache-dir`: reuse a local Hugging Face cache
- `--revision`: pin the download to a specific dataset revision
- `--extract-prompts`: export the `prompts` list into `prompts.jsonl` for easier ingestion with tooling that expects JSONL

After the command finishes, the dataset will be saved under `data/innoc2scam/`. Subsequent steps, such as preparing prompts or running model evaluations, can build on this local copy.

## Step 2: Validate prompts with an LLM

Use `validate_llms.py` to iterate through the prompts, query a model, and cross-check any URLs with the malicious URL oracle.

```bash
python3 validate_llms.py --model openrouter/openai/gpt-4o-mini --limit 5
```

Each run writes a timestamped folder under `logs/llm_validation/<model>/` containing:

- `validation.log` and `responses.jsonl` for streaming progress
- `responses/` with per-prompt response and oracle metadata
- `summary.json` with aggregate counts of generated and malicious URLs
