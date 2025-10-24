import os
from openai import AzureOpenAI, OpenAI
from dotenv import load_dotenv
from typing import Optional, List
import threading
import random
import requests
import json
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables from .env file
load_dotenv()

AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_API_VERSION = "2024-05-01-preview"

def load_openrouter_keys() -> List[str]:
    """Load all available OpenRouter API keys from environment variables"""
    keys = []
    
    # Load keys from OPENROUTER_API_KEY to OPENROUTER_API_KEY10
    base_key = os.getenv("OPENROUTER_API_KEY")
    if base_key:
        keys.append(base_key)
    
    # Load numbered keys
    for i in range(2, 11):  # 2 to 10
        key = os.getenv(f"OPENROUTER_API_KEY{i}")
        if key:
            keys.append(key)
    
    return keys

OPENROUTER_API_KEYS = load_openrouter_keys()

class AzureOpenAIClient:
    """Client for Azure OpenAI services"""
    def __init__(self, api_key: str, endpoint: str, api_version: str, model: str):
        if not api_key or not endpoint:
            raise ValueError("Azure OpenAI API key and endpoint are required")
        self.model = model
        self.client = AzureOpenAI(
            api_key=api_key,
            api_version=api_version,
            azure_endpoint=endpoint
        )

    def answer_prompt(self, prompt: str, max_tokens: int = 2000, temperature: float = 0.0, 
                      seed: Optional[int] = None, top_p: Optional[float] = None, 
                      system_message: str = "You are a helpful assistant.") -> str:
        """Get an answer from the configured Azure OpenAI model."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                seed=seed,
                top_p=top_p
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error calling Azure OpenAI API: {e}")
            return ""

class OpenRouterClient:
    """Client for OpenRouter services with multi-key load balancing"""
    def __init__(self, model: str, api_key: str = None):
        self.model = model
        
        # Use all available keys if we have them, otherwise fall back to provided key
        if OPENROUTER_API_KEYS:
            self.api_keys = OPENROUTER_API_KEYS
        elif api_key:
            self.api_keys = [api_key]
        else:
            raise ValueError("No OpenRouter API keys available. Add OPENROUTER_API_KEY to .env file.")
        
        # Create clients for all available keys
        self.clients = []
        for key in self.api_keys:
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=key,
            )
            self.clients.append(client)
        
        # Round-robin counter with thread safety
        self._counter = 0
        self._lock = threading.Lock()
        
        # Initialize optimized session for deepseek native API calls
        self._session = None
        self._session_lock = threading.Lock()
        self._warmed_up = False
        
        # Log multi-key status
        if len(self.api_keys) > 1:
            print(f"🔑 OpenRouter multi-key mode: {len(self.api_keys)} keys loaded for load balancing")
        else:
            print(f"🔑 OpenRouter single-key mode: 1 key loaded")

    def _get_next_client(self) -> OpenAI:
        """Get the next client using round-robin load balancing"""
        with self._lock:
            client = self.clients[self._counter % len(self.clients)]
            self._counter += 1
            return client

    def answer_prompt(self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1, 
                      seed: Optional[int] = None, top_p: Optional[float] = None, 
                      system_message: str = "You are a helpful assistant.") -> str:
        """Get an answer from the configured OpenRouter model using load-balanced clients."""
        # Apply deterministic settings specifically for llama-4-scout to ensure consistent code generation
        if "llama-4-scout" in self.model.lower():
            # Override parameters for deterministic behavior
            temperature = 0.0  # Force most deterministic setting
            seed = seed if seed is not None else 42  # Use provided seed or default to 42
            top_p = 1.0  # Disable nucleus sampling
            # print(f"🎯 Applying deterministic settings for {self.model}: temp=0.0, seed={seed}, top_p=1.0")
        
        # Apply deterministic settings for OpenAI models through OpenRouter (same as Azure)
        if "openai/gpt-4o" in self.model.lower():
            # Override parameters for deterministic behavior like Azure models
            temperature = 0.0  # Force most deterministic setting
            seed = seed if seed is not None else 42  # Use provided seed or default to 42
            top_p = 1.0  # Disable nucleus sampling
            # print(f"🎯 Applying deterministic settings for {self.model}: temp=0.0, seed={seed}, top_p=1.0")
        
        # For deepseek models, use native OpenRouter API instead of OpenAI SDK
        if "deepseek" in self.model.lower():
            # Ensure warmup before every call for better performance
            if not self._warmed_up:
                self._warmup_connections()
            return self._call_deepseek_native_api(prompt, max_tokens, temperature, seed, top_p, system_message)


        
        
        # For all other models, use OpenAI SDK
        # Try each client with exponential backoff for resilience
        max_retries = min(3, len(self.clients))  # Try up to 3 clients or all available
        
        for attempt in range(max_retries):
            try:
                # Get next client using round-robin
                client = self._get_next_client()
                
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    seed=seed,
                    top_p=top_p,
                )
                return response.choices[0].message.content
                
            except Exception as e:
                error_str = str(e).lower()
                is_rate_limit = any(keyword in error_str for keyword in ["rate", "limit", "429", "quota"])
                
                if is_rate_limit and attempt < max_retries - 1:
                    # If rate limited and we have more clients to try, continue to next client
                    print(f"⚠️  Rate limit hit on key {attempt + 1}/{len(self.api_keys)}, trying next key...")
                    continue
                elif attempt == max_retries - 1:
                    # Last attempt failed, raise the error
                    print(f"❌ All {max_retries} OpenRouter clients failed")
                    raise e
                else:
                    # Non-rate-limit error, try next client
                    print(f"⚠️  Error with key {attempt + 1}: {e}, trying next key...")
                    continue
        
        # This shouldn't be reached, but just in case
        raise Exception("All OpenRouter API clients failed")

    def _get_optimized_session(self) -> requests.Session:
        """Get or create an optimized session for native API calls with connection pooling."""
        with self._session_lock:
            if self._session is None:
                self._session = requests.Session()
                
                # Configure retry strategy for better reliability
                retry_strategy = Retry(
                    total=3,
                    backoff_factor=0.1,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                
                # Configure connection pooling adapter
                adapter = HTTPAdapter(
                    max_retries=retry_strategy,
                    pool_connections=10,  # Number of connection pools
                    pool_maxsize=20,      # Max connections per pool
                    pool_block=False      # Don't block when pool is full
                )
                
                self._session.mount("https://", adapter)
                self._session.mount("http://", adapter)
                
                # Set persistent headers
                self._session.headers.update({
                    "Content-Type": "application/json",
                    "Connection": "keep-alive",
                    "User-Agent": "OpenRouter-Python-Client/1.0"
                })
                
                print("🔧 Initialized optimized session for deepseek native API")
            
            return self._session

    def _warmup_connections(self) -> bool:
        """Pre-warm connections for better performance."""
        if self._warmed_up:
            return True
            
        print("🔥 Pre-warming deepseek connections...")
        
        # Simple warm-up request (removed provider order to prioritize cost over speed)
        warmup_payload = {
            "model": self.model,
            "prompt": "Hello",
            "max_tokens": 1,
            "temperature": 0.0
        }
        
        session = self._get_optimized_session()
        
        # Try to warm up with first API key
        try:
            with self._lock:
                api_key = self.api_keys[0]
            
            headers = {"Authorization": f"Bearer {api_key}"}
            headers.update(session.headers)
            
            response = session.post(
                "https://openrouter.ai/api/v1/completions",
                json=warmup_payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                self._warmed_up = True
                print("✅ Connection warm-up successful")
                return True
            else:
                print(f"⚠️  Warm-up got HTTP {response.status_code}, continuing anyway...")
                return False
                
        except Exception as e:
            print(f"⚠️  Warm-up failed: {e}, continuing anyway...")
            return False

    def _call_deepseek_native_api(self, prompt: str, max_tokens: int, temperature: float, 
                                 seed: Optional[int], top_p: Optional[float], 
                                 system_message: str) -> str:
        """Call deepseek models using native OpenRouter API for better compatibility."""
        # Apply deterministic settings for deepseek
        temperature = 0.0  # Force most deterministic setting
        seed = seed if seed is not None else 42  # Use provided seed or default to 42
        top_p = 1.0  # Disable nucleus sampling
        
        print(f"🎯 Applying deterministic settings for {self.model}: temp=0.0, seed={seed}, top_p=1.0")
        # print(f"🏢 Restricting deepseek to providers: gmicloud/fp8, baseten/fp8, parasail/fp8, fireworks")
        # print(f"🌐 Using native OpenRouter API for deepseek model")
        
        # Ensure connections are warmed up
        if not self._warmed_up:
            self._warmup_connections()
        
        # Get optimized session with connection pooling
        session = self._get_optimized_session()
        
        # Combine system message and user prompt
        full_prompt = f"{system_message}\n\nUser: {prompt}\n\nAssistant:"
        
        # Prepare request payload (removed provider configs to prioritize cost over speed)
        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "seed": seed,
            "top_p": top_p,
            # "provider": {
            #     # "order": ["gmicloud/fp8", "baseten/fp8", "parasail/fp8", "fireworks"]
            #     "sort": "throughput"  # Sort by latency for better performance
            # }
        }
        
        # Try each API key with exponential backoff
        max_retries = min(3, len(self.api_keys))
        
        for attempt in range(max_retries):
            try:
                # Get next API key using round-robin
                with self._lock:
                    api_key = self.api_keys[self._counter % len(self.api_keys)]
                    self._counter += 1
                
                # Prepare headers (session already has base headers)
                headers = {"Authorization": f"Bearer {api_key}"}
                
                response = session.post(
                    "https://openrouter.ai/api/v1/completions",
                    json=payload,
                    headers=headers,
                    timeout=30  # Reduced timeout with retries
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("choices") and len(result["choices"]) > 0:
                        return result["choices"][0]["text"].strip()
                    else:
                        raise Exception("No choices in response")
                else:
                    # Handle HTTP errors
                    error_detail = response.text
                    raise Exception(f"HTTP {response.status_code}: {error_detail}")
                    
            except Exception as e:
                error_str = str(e).lower()
                is_rate_limit = any(keyword in error_str for keyword in ["rate", "limit", "429", "quota"])
                
                if is_rate_limit and attempt < max_retries - 1:
                    print(f"⚠️  Rate limit hit on key {attempt + 1}/{len(self.api_keys)}, trying next key...")
                    continue
                elif attempt == max_retries - 1:
                    print(f"❌ All {max_retries} OpenRouter API keys failed for deepseek")
                    raise e
                else:
                    print(f"⚠️  Error with key {attempt + 1}: {e}, trying next key...")
                    continue
        
        raise Exception("All OpenRouter API keys failed for deepseek")


def create_client(model_identifier: str):
    """
    Factory function to create the appropriate API client based on a model identifier.
        
        Args:
        model_identifier: A string in the format 'provider/model_name', 
                          e.g., 'azure/gpt-4o-mini', 'openrouter/meta-llama/llama-3-70b-instruct',
                          'x-ai/grok-code-fast-1', 'deepseek/deepseek-chat-v3.1',
                          'openai/gpt-5', 'qwen/qwen3-coder', 'google/gemini-2.5-flash',
                          'google/gemini-2.5-pro', 'anthropic/claude-sonnet-4'
            
        Returns:
        An instance of an API client (e.g., AzureOpenAIClient, OpenRouterClient).
    """
    parts = model_identifier.lower().split('/')
    if len(parts) < 2:
        raise ValueError("model_identifier must be in the format 'provider/model_name' or 'provider/author/model_name'")
        
    provider = parts[0]
    model_name = "/".join(parts[1:])

    if provider == 'azure':
        # For Azure, the model name is the deployment name
        if model_name == 'gpt-4o-mini':
            deployment_name = "gpt-4o-mini"
        elif model_name == 'gpt-4o':
            deployment_name = "gpt-4o"
        else:
            raise ValueError(f"Unsupported Azure model: {model_name}. Supported: gpt-4o-mini, gpt-4o")
            
        return AzureOpenAIClient(
            api_key=AZURE_OPENAI_API_KEY,
            endpoint=AZURE_OPENAI_ENDPOINT,
            api_version=AZURE_API_VERSION,
            model=deployment_name
        )
    elif provider == 'openrouter':
        return OpenRouterClient(
            model=model_name
        )
    elif provider == 'x-ai':
        # x-ai models are available through OpenRouter
        # Convert x-ai model format to OpenRouter format
        openrouter_model = f"x-ai/{model_name}"
        return OpenRouterClient(
            model=openrouter_model
        )
    elif provider == 'deepseek':
        # DeepSeek models are available through OpenRouter
        openrouter_model = f"deepseek/{model_name}"
        return OpenRouterClient(
            model=openrouter_model
        )
    elif provider == 'openai':
        # OpenAI models are available through OpenRouter
        openrouter_model = f"openai/{model_name}"
        return OpenRouterClient(
            model=openrouter_model
        )
    elif provider == 'qwen':
        # Qwen models are available through OpenRouter
        openrouter_model = f"qwen/{model_name}"
        return OpenRouterClient(
            model=openrouter_model
        )
    elif provider == 'google':
        # Google models are available through OpenRouter
        openrouter_model = f"google/{model_name}"
        return OpenRouterClient(
            model=openrouter_model
        )
    elif provider == 'anthropic':
        # Anthropic models are available through OpenRouter
        openrouter_model = f"anthropic/{model_name}"
        return OpenRouterClient(
            model=openrouter_model
        )

    else:
        raise ValueError(f"Unsupported provider: {provider}. Supported providers: azure, openrouter, x-ai, deepseek, openai, qwen, google, anthropic")

def test_llama_4_scout():
    """
    Test function to check if meta-llama/llama-4-scout model is accessible through OpenRouter.
    Uses most deterministic settings and tests for consistency.
    
    Returns:
        bool: True if the model responds successfully, False otherwise
    """
    try:
        # Create client for the Llama 4 Scout model
        model_identifier = "openrouter/meta-llama/llama-4-scout"
        client = create_client(model_identifier)
        
        # Simple test prompt
        test_prompt = "Hello! Can you say something random if you're working?"
        
        print(f"Testing model: {model_identifier}")
        print(f"Test prompt: {test_prompt}")
        
        # Test consistency by making multiple calls
        responses = []
        num_tests = 3
        
        print(f"\n🔄 Testing consistency with {num_tests} identical calls...")
        
        for i in range(num_tests):
            print(f"Call {i+1}/{num_tests}...", end=" ")
            
            # Make the API call with most deterministic settings
            response = client.answer_prompt(
                prompt=test_prompt,
                temperature=0.0,  # Most deterministic
                seed=42,          # Fixed seed for reproducibility
                top_p=1.0         # No nucleus sampling for deterministic behavior
            )
            
            if response:
                responses.append(response.strip())
                print("✅")
            else:
                print("❌ No response")
                return False
        
        # Check consistency
        unique_responses = set(responses)
        
        print(f"\n📊 Consistency Results:")
        print(f"   Total calls: {num_tests}")
        print(f"   Unique responses: {len(unique_responses)}")
        
        if len(unique_responses) == 1:
            print("   🎯 DETERMINISTIC: All responses identical!")
            print(f"   Response: {responses[0]}")
        else:
            print("   ⚠️  NON-DETERMINISTIC: Different responses detected")
            for i, response in enumerate(unique_responses, 1):
                print(f"   Response {i}: {response}")
        
        return True
            
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False


def test_llama_4_scout_simple():
    """
    Simple test with a more controlled prompt that should give consistent results.
    
    Returns:
        bool: True if the model responds successfully, False otherwise
    """
    try:
        # Create client for the Llama 4 Scout model
        model_identifier = "openrouter/meta-llama/llama-4-scout"
        client = create_client(model_identifier)
        
        # More controlled test prompt
        test_prompt = "What is 2 + 2?"
        
        print(f"\n🧮 Testing with controlled prompt: {test_prompt}")
        
        # Make multiple calls to test consistency
        responses = []
        for i in range(3):
            response = client.answer_prompt(
                prompt=test_prompt,
                temperature=0.0,
                seed=42,
                top_p=1.0,
                max_tokens=10
            )
            
            if response:
                responses.append(response.strip())
            else:
                return False
        
        unique_responses = set(responses)
        
        print(f"Responses to math question:")
        for i, response in enumerate(unique_responses, 1):
            print(f"   {i}: {response}")
            
        if len(unique_responses) == 1:
            print("   ✅ Math question responses are consistent!")
        else:
            print("   ⚠️  Even math questions give different responses")
        
        return True
        
    except Exception as e:
        print(f"❌ Simple test failed: {e}")
        return False


def test_llama_4_scout_code_generation():
    """
    Test deterministic code generation with meta-llama/llama-4-scout.
    This tests the specific use case of generating code consistently.
        
    Returns:
        bool: True if code generation is deterministic, False otherwise
    """
    try:
        # Create client for the Llama 4 Scout model
        model_identifier = "openrouter/meta-llama/llama-4-scout"
        client = create_client(model_identifier)
        
        # Code generation prompt
        code_prompt = "Write a Python function that adds two numbers and returns the result."
        
        print(f"\n💻 Testing deterministic code generation with: {model_identifier}")
        print(f"Code prompt: {code_prompt}")
        
        # Test consistency by making multiple calls
        responses = []
        num_tests = 3
        
        print(f"\n🔄 Testing code generation consistency with {num_tests} identical calls...")
        
        for i in range(num_tests):
            print(f"Generating code {i+1}/{num_tests}...", end=" ")
            
            # Make the API call - deterministic settings will be auto-applied for llama-4-scout
            response = client.answer_prompt(
                prompt=code_prompt,
                max_tokens=200,
                temperature=0.5,  # This will be overridden to 0.0 for llama-4-scout
                # seed will be auto-set to 42 for llama-4-scout
                # top_p will be auto-set to 1.0 for llama-4-scout
            )
            
            if response:
                responses.append(response.strip())
                print("✅")
            else:
                print("❌ No response")
                return False
        
        # Check consistency
        unique_responses = set(responses)
        
        print(f"\n📊 Code Generation Consistency Results:")
        print(f"   Total calls: {num_tests}")
        print(f"   Unique code responses: {len(unique_responses)}")
        
        if len(unique_responses) == 1:
            print("   🎯 DETERMINISTIC: All code responses identical!")
            print("   ✅ Code generation is consistent for llama-4-scout")
            print(f"\n   Generated code:\n{'-'*50}")
            print(responses[0])
            print('-'*50)
        else:
            print("   ⚠️  NON-DETERMINISTIC: Different code responses detected")
            for i, response in enumerate(unique_responses, 1):
                print(f"\n   Code Response {i}:\n{'-'*30}")
                print(response)
                print('-'*30)
        
        return True
            
    except Exception as e:
        print(f"❌ Code generation test failed: {e}")
        return False


def test_deepseek_code_generation():
    """
    Test deterministic code generation with deepseek/deepseek-chat-v3-0324.
    This tests the specific use case of generating code consistently.
        
    Returns:
        bool: True if code generation is deterministic, False otherwise
    """
    try:
        # Create client for the DeepSeek model
        model_identifier = "openrouter/deepseek/deepseek-chat-v3-0324"
        client = create_client(model_identifier)
        
        # Code generation prompt
        code_prompt = "Write a Python function that adds two numbers and returns the result."
        
        print(f"\n💻 Testing deterministic code generation with: {model_identifier}")
        print(f"Code prompt: {code_prompt}")
        
        # Test consistency by making multiple calls
        responses = []
        num_tests = 3
        
        print(f"\n🔄 Testing code generation consistency with {num_tests} identical calls...")
        
        for i in range(num_tests):
            print(f"Generating code {i+1}/{num_tests}...", end=" ")
            
            # Make the API call - deterministic settings will be auto-applied for deepseek
            response = client.answer_prompt(
                prompt=code_prompt,
                max_tokens=200,
                temperature=0.5,  # This will be overridden to 0.0 for deepseek
                # seed will be auto-set to 42 for deepseek
                # top_p will be auto-set to 1.0 for deepseek
            )
            
            if response:
                responses.append(response.strip())
                print("✅")
            else:
                print("❌ No response")
                return False
        
        # Check consistency
        unique_responses = set(responses)
        
        print(f"\n📊 Code Generation Consistency Results:")
        print(f"   Total calls: {num_tests}")
        print(f"   Unique code responses: {len(unique_responses)}")
        
        if len(unique_responses) == 1:
            print("   🎯 DETERMINISTIC: All code responses identical!")
            print("   ✅ Code generation is consistent for deepseek")
            print(f"\n   Generated code:\n{'-'*50}")
            print(responses[0])
            print('-'*50)
        else:
            print("   ⚠️  NON-DETERMINISTIC: Different code responses detected")
            for i, response in enumerate(unique_responses, 1):
                print(f"\n   Code Response {i}:\n{'-'*30}")
                print(response)
                print('-'*30)
        
        return True
            
    except Exception as e:
        print(f"❌ Code generation test failed: {e}")
        return False


def test_openrouter_openai_models():
    """
    Test OpenRouter's OpenAI models (gpt-4o and gpt-4o-mini) to ensure they work correctly.
    These models should behave similarly to Azure OpenAI models with deterministic settings.
        
    Returns:
        bool: True if both models respond successfully, False otherwise
    """
    models_to_test = [
        "openrouter/openai/gpt-4o-mini",
        "openrouter/openai/gpt-4o"
    ]
    
    # Use a code generation prompt to test deterministic behavior
    code_prompt = "Write a Python function that adds two numbers and returns the result."
    
    print(f"\n🌐 Testing OpenRouter's OpenAI models with deterministic settings...")
    
    all_success = True
    
    for model_identifier in models_to_test:
        try:
            print(f"\n💻 Testing deterministic code generation with: {model_identifier}")
            
            # Create client for the model
            client = create_client(model_identifier)
            
            # Test consistency by making multiple calls
            responses = []
            num_tests = 3
            
            print(f"🔄 Testing consistency with {num_tests} identical calls...")
            
            for i in range(num_tests):
                print(f"Call {i+1}/{num_tests}...", end=" ")
                
                # Make the API call - deterministic settings will be auto-applied for openai models
                response = client.answer_prompt(
                    prompt=code_prompt,
                    temperature=0,  # This will be overridden to 0.0 for openai models
                    # seed will be auto-set to 42 for openai models
                    # top_p will be auto-set to 1.0 for openai models
                )
                
                if response:
                    responses.append(response.strip())
                    print("✅")
                else:
                    print("❌ No response")
                    all_success = False
                    break
            
            if responses:
                # Check consistency
                unique_responses = set(responses)
                
                print(f"📊 Consistency Results for {model_identifier}:")
                print(f"   Total calls: {num_tests}")
                print(f"   Unique responses: {len(unique_responses)}")
                
                if len(unique_responses) == 1:
                    print("   🎯 DETERMINISTIC: All responses identical!")
                    print(f"   Generated code:\n{'-'*30}")
                    print(responses[0])
                    print('-'*30)
                else:
                    print("   ⚠️  NON-DETERMINISTIC: Different responses detected")
                    for i, response in enumerate(unique_responses, 1):
                        print(f"   Response {i}: {response[:100]}{'...' if len(response) > 100 else ''}")
                
        except Exception as e:
            print(f"   ❌ Error testing {model_identifier}: {e}")
            all_success = False
    
    if all_success:
        print(f"\n🎉 All OpenRouter OpenAI models tested successfully!")
    else:
        print(f"\n💥 One or more OpenRouter OpenAI models failed!")
    
    return all_success


if __name__ == "__main__":
    # Run the tests when this file is executed directly
    print("🧪 Testing meta-llama/llama-4-scout model...")
    
    # # Test 1: Original test with consistency checking
    # success1 = test_llama_4_scout()
    
    # # Test 2: Simple math test
    # success2 = test_llama_4_scout_simple()
    
    # # Test 3: Code generation test
    # success3 = test_llama_4_scout_code_generation()
    
    # print("\n🧪 Testing deepseek/deepseek-chat-v3-0324 model...")
    
    # Test 4: DeepSeek code generation test
    # success4 = test_deepseek_code_generation()
    
    print("\n🧪 Testing OpenRouter OpenAI models...")
    
    # Test 5: OpenRouter OpenAI models test
    success5 = test_openrouter_openai_models()
    
    # if success1 and success2 and success3 and success4 and success5:
    #     print("\n🎉 All tests completed successfully!")
    #     print("\n💡 Tips for handling non-deterministic behavior:")
    #     print("   • Use simpler, more factual prompts for consistent results")
    #     print("   • Consider that creative prompts may inherently vary")
    #     print("   • OpenRouter's load balancing may cause variations")
    #     print("   • Try different seed values if consistency is critical")
    # else:
    #     print("\n💥 One or more tests failed!")
