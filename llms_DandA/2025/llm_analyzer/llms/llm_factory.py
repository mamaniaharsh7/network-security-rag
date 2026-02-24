#!/usr/bin/env python3
"""
LLM Factory - Clean and Complete
Factory class for creating and managing different LLM clients
"""

from typing import Dict, List, Type
from base_llm_client import BaseLLMClient
from deepseek_client import DeepSeekClient
from ollama_client import OllamaClient
from openai_client import OpenAIClient
from anthropic_client import AnthropicClient

# Import Cisco local client
try:
    from cisco_local_client import CiscoFoundationLocalClient
    CISCO_AVAILABLE = True
except ImportError:
    print("⚠️  Cisco Foundation local client not found - skipping")
    CiscoFoundationLocalClient = None
    CISCO_AVAILABLE = False

class LLMFactory:
    """
    Factory class for creating LLM clients
    Manages provider registration and client creation
    """
    
    # Registry of available providers
    PROVIDERS: Dict[str, Type[BaseLLMClient]] = {
        'deepseek': DeepSeekClient,
        'ollama': OllamaClient,
        'openai': OpenAIClient,
        'anthropic': AnthropicClient
    }
    
    # Add Cisco if available
    if CISCO_AVAILABLE:
        PROVIDERS['cisco'] = CiscoFoundationLocalClient
    
    @classmethod
    def create_client(cls, provider: str, **kwargs) -> BaseLLMClient:
        """
        Create an LLM client for the specified provider
        
        Args:
            provider: Provider name (deepseek, ollama, openai, anthropic, cisco)
            **kwargs: Provider-specific configuration
            
        Returns:
            LLM client instance
            
        Raises:
            ValueError: If provider is not supported
        """
        provider = provider.lower()
        
        if provider not in cls.PROVIDERS:
            available = ", ".join(cls.PROVIDERS.keys())
            raise ValueError(f"Unsupported provider '{provider}'. Available: {available}")
        
        # Debug: Print what arguments we're passing
        if provider == 'cisco':
            print(f"🔧 Creating Cisco local client with args: {list(kwargs.keys())}")
            # Cisco local client doesn't need api_key, just model name
            if 'api_key' in kwargs:
                kwargs.pop('api_key')  # Remove api_key for local client
                print(f"💡 Removed api_key for local Cisco client")
        
        try:
            return cls.PROVIDERS[provider](**kwargs)
        except TypeError as e:
            # Provide helpful error message
            raise TypeError(f"Error creating {provider} client: {e}. Check required parameters in help.")
        except Exception as e:
            raise Exception(f"Failed to create {provider} client: {e}")
    
    @classmethod
    def register_provider(cls, name: str, client_class: Type[BaseLLMClient]):
        """
        Register a new LLM provider
        
        Args:
            name: Provider name
            client_class: LLM client class that inherits from BaseLLMClient
        """
        if not issubclass(client_class, BaseLLMClient):
            raise ValueError("Client class must inherit from BaseLLMClient")
        
        cls.PROVIDERS[name.lower()] = client_class
        print(f"✅ Registered LLM provider: {name}")
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """
        Get list of available LLM providers
        
        Returns:
            List of provider names
        """
        return list(cls.PROVIDERS.keys())
    
    @classmethod
    def get_provider_help(cls, provider: str) -> str:
        """
        Get help text for a specific provider
        
        Args:
            provider: Provider name
            
        Returns:
            Help text string
        """
        help_text = {
            'deepseek': """
DeepSeek Configuration:
  Required: api_key
  Optional: base_url, model (default: deepseek-chat)
  Example: --provider deepseek --api-key-file config/keys/deepseek_key.txt
  
  Models: deepseek-chat, deepseek-coder
  Website: https://platform.deepseek.com/
            """,
            
            'ollama': """
Ollama Configuration:
  Required: model
  Optional: base_url (default: http://localhost:11434)
  Example: --provider ollama --model qwen2.5:7b
  
  Recommended Models (2025):
    • qwen2.5:7b - Excellent general model
    • qwen2.5:3b - Faster, lighter model
    • deepseek-r1:8b - Strong reasoning
    • gemma2:9b - Efficient performance
    • phi4:14b - Microsoft's latest
  
  Setup:
    1. Install: https://ollama.ai/
    2. Start: ollama serve
    3. Pull model: ollama pull qwen2.5:7b
            """,
            
            'openai': """
OpenAI Configuration:
  Required: api_key
  Optional: base_url, model (default: gpt-3.5-turbo)
  Example: --provider openai --api-key-file config/keys/openai_key.txt --model gpt-4
  
  Models: gpt-3.5-turbo, gpt-4, gpt-4-turbo
  Website: https://platform.openai.com/
            """,
            
            'anthropic': """
Anthropic Configuration:
  Required: api_key
  Optional: base_url, model (default: claude-sonnet-4-20250514)
  Example: --provider anthropic --api-key-file config/keys/anthropic_key.txt
  
  Current Models (2025):
    • claude-sonnet-4-20250514 (latest Claude 4 Sonnet)
    • claude-opus-4-1-20250805 (Claude 4 Opus)
    • claude-3-5-sonnet-20241022 (Claude 3.5 Sonnet)
    • claude-3-opus-20240229 (Claude 3 Opus - reliable fallback)
    • claude-3-haiku-20240307 (Claude 3 Haiku - fast)
  
  Setup:
    1. Get API key: https://console.anthropic.com/
    2. Save to file: echo 'your-api-key' > config/keys/anthropic_key.txt
    3. Use: --provider anthropic --api-key-file config/keys/anthropic_key.txt
    
  If getting 404 errors, try older models:
    --provider anthropic --model claude-3-5-sonnet-20241022
  Website: https://console.anthropic.com/
            """,
            
            'cisco': """
Cisco Foundation-Sec-8B Configuration (LOCAL):
  Required: None (runs locally)
  Optional: model (default: fdtn-ai/Foundation-Sec-8B-Instruct)
  Example: --provider cisco --model fdtn-ai/Foundation-Sec-8B-Instruct
  
  Models: 
    • fdtn-ai/Foundation-Sec-8B-Instruct (recommended for chat)
    • fdtn-ai/Foundation-Sec-8B (base model)
  
  Features:
    • 🛡️ Specialized for cybersecurity analysis
    • 📊 Trained on threat intelligence, CVEs, MITRE ATT&CK
    • 🏠 Runs completely local (no API needed)
    • 🔒 Maximum privacy and security
    • 🔓 Open-source (Apache 2.0 license)
  
  Setup:
    1. Install dependencies: pip install transformers torch
    2. Optional (memory efficiency): pip install bitsandbytes
    3. Use: --provider cisco (no API key needed)
    
  Requirements:
    • ~15GB disk space for model download
    • 8GB+ RAM (with 8-bit quantization)
    • 16GB+ RAM (standard loading)
    • GPU recommended but not required
    
  Why Choose Cisco for Security Analysis:
    • Purpose-built for cybersecurity workflows
    • Understands security terminology and concepts
    • Optimized for SOC operations and incident response
    • Trained specifically on threat intelligence data
    • Runs locally for maximum data privacy
            """ if CISCO_AVAILABLE else "Cisco Foundation local client not available - missing cisco_local_client.py"
        }
        
        return help_text.get(provider.lower(), "No help available for this provider")

# Clean test functionality
if __name__ == "__main__":
    import sys
    
    print("🧪 LLM Factory Test")
    print("=" * 30)
    
    # Show available providers
    providers = LLMFactory.get_available_providers()
    print(f"Available providers: {', '.join(providers)}")
    
    # Test provider help
    if len(sys.argv) > 1:
        provider = sys.argv[1].lower()
        
        if provider in providers:
            print(f"\n📋 Help for {provider}:")
            print(LLMFactory.get_provider_help(provider))
            
            # Test client creation (without actual connection)
            try:
                if provider == "ollama":
                    client = LLMFactory.create_client("ollama", model="qwen2.5:7b")
                    print(f"✅ Created {provider} client: {client.get_provider_name()}")
                elif provider == "cisco":
                    print(f"💡 To test {provider}, provide Hugging Face API key as second argument")
                    if len(sys.argv) > 2:
                        client = LLMFactory.create_client("cisco", api_key=sys.argv[2])
                        print(f"✅ Created {provider} client: {client.get_provider_name()}")
                        # Show model info if available
                        if hasattr(client, 'get_model_info'):
                            info = client.get_model_info()
                            print(f"🛡️  Specialization: {info['specialization']}")
                            print(f"📊 Parameters: {info['parameters']}")
                elif provider in ["deepseek", "openai", "anthropic"]:
                    print(f"💡 To test {provider}, provide API key as second argument")
                    if len(sys.argv) > 2:
                        client = LLMFactory.create_client(provider, api_key=sys.argv[2])
                        print(f"✅ Created {provider} client: {client.get_provider_name()}")
                        
            except Exception as e:
                print(f"❌ Error creating {provider} client: {e}")
        else:
            print(f"❌ Unknown provider: {provider}")
            print(f"Available: {', '.join(providers)}")
    else:
        print("\n💡 Usage:")
        print("  python llm_factory.py <provider> [api_key]")
        print("  python llm_factory.py ollama")
        print("  python llm_factory.py cisco <huggingface_token>")
        print("  python llm_factory.py deepseek <api_key>")
        
        print("\n🛡️  NEW: Cisco Foundation-Sec-8B")
        print("  • First LLM trained specifically for cybersecurity")
        print("  • Perfect for your security incident analyzer")
        print("  • Free tier available via Hugging Face")
        print("  • Understands MITRE ATT&CK, CVEs, threat intelligence")
