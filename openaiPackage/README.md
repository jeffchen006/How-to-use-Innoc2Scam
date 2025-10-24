# OpenAI Package

Utilities for exercising hosted LLMs through Azure and OpenRouter. The main entry point is `openaiClient.py`, which bundles:

- `AzureOpenAIClient` for Azure-hosted GPT deployments.
- `OpenRouterClient` with API-key rotation, deterministic settings for specific models, and native HTTP calls for DeepSeek.
- Convenience tests that probe model determinism and API wiring.

## Requirements

Install the dependencies referenced in `requirements.txt` (ensure `openai`, `python-dotenv`, and `requests` are available) and populate your `.env` file with the necessary keys:

- `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` (if you plan to exercise Azure)
- `OPENROUTER_API_KEY` plus optional `OPENROUTER_API_KEY2` … `OPENROUTER_API_KEY10`

## Quick Test

To verify the OpenRouter configuration and see the diagnostic output, run:

```bash
python3 openaiPackage/openaiClient.py
```

Expected console output:

```
🧪 Testing meta-llama/llama-4-scout model...

🧪 Testing OpenRouter OpenAI models...

🌐 Testing OpenRouter's OpenAI models with deterministic settings...

💻 Testing deterministic code generation with: openrouter/openai/gpt-4o-mini
🔑 OpenRouter single-key mode: 1 key loaded
🔄 Testing consistency with 3 identical calls...
Call 1/3... ✅
Call 2/3... ✅
Call 3/3... ✅
📊 Consistency Results for openrouter/openai/gpt-4o-mini:
   Total calls: 3
   Unique responses: 2
   ⚠️  NON-DETERMINISTIC: Different responses detected
   Response 1: Certainly! Here is a simple Python function that adds two numbers and returns the result:

```python...
   Response 2: Certainly! Here is a simple Python function that adds two numbers and returns the result:

```python...

💻 Testing deterministic code generation with: openrouter/openai/gpt-4o
🔑 OpenRouter single-key mode: 1 key loaded
🔄 Testing consistency with 3 identical calls...
Call 1/3... ✅
Call 2/3... ✅
Call 3/3... ✅
📊 Consistency Results for openrouter/openai/gpt-4o:
   Total calls: 3
   Unique responses: 3
   ⚠️  NON-DETERMINISTIC: Different responses detected
   Response 1: Certainly! Below is a simple Python function that takes two numbers as input and returns their sum:
...
   Response 2: Certainly! Below is a simple Python function that takes two numbers as arguments, adds them together...
   Response 3: Certainly! Below is a simple Python function that takes two numbers as input and returns their sum:
...

🎉 All OpenRouter OpenAI models tested successfully!
```
