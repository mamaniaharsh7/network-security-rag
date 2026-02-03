#!/usr/bin/env python3
"""
Ollama LLM Client
Implementation for local Ollama models
"""

import requests
from typing import Optional
from base_llm_client import BaseLLMClient

class OllamaClient(BaseLLMClient):
    """
    Ollama local LLM client for running models locally
    """
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5:7b", **kwargs):
        """
        Initialize Ollama client
        
        Args:
            base_url: Ollama server URL
            model: Model name to use
            **kwargs: Additional configuration
        """
        super().__init__(base_url=base_url, model=model, **kwargs)
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.generate_url = f"{self.base_url}/api/generate"
        self.chat_url = f"{self.base_url}/api/chat"
        self.tags_url = f"{self.base_url}/api/tags"
    
    def query(self, prompt: str, max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        """
        Send query to Ollama
        
        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            **kwargs: Additional options
            
        Returns:
            Model response text or error message
        """
        # Try chat format first (preferred for newer models)
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        # Add any additional options
        if kwargs:
            payload["options"].update(kwargs)
        
        try:
            response = requests.post(self.chat_url, json=payload, timeout=300)  # Longer timeout for local
            if response.status_code == 200:
                result = response.json()
                return result.get('message', {}).get('content', "❌ No content in response")
        except:
            pass  # Fall back to generate endpoint
        
        # Fallback to generate endpoint for older models
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        if kwargs:
            payload["options"].update(kwargs)
        
        try:
            response = requests.post(self.generate_url, json=payload, timeout=300)
            response.raise_for_status()
            
            result = response.json()
            return result.get('response', "❌ No response content")
            
        except requests.exceptions.Timeout:
            return "❌ Ollama Timeout: Request took too long"
        except requests.exceptions.ConnectionError:
            return f"❌ Ollama Connection Error: Is Ollama running on {self.base_url}?"
        except requests.exceptions.RequestException as e:
            return f"❌ Ollama API Error: {e}"
        except Exception as e:
            return f"❌ Unexpected error: {e}"
    
    def test_connection(self) -> bool:
        """
        Test if Ollama is running and model is available
        
        Returns:
            True if connection successful
        """
        try:
            # Test if Ollama is running
            response = requests.get(self.tags_url, timeout=10)
            if response.status_code != 200:
                print(f"❌ Ollama server not responding: {response.status_code}")
                return False
            
            # Check if model exists
            models = response.json().get('models', [])
            model_names = [m['name'] for m in models]
            
            # Check for exact match or partial match (handles tags like :7b)
            model_found = any(
                self.model == name or 
                self.model in name or 
                name.startswith(self.model.split(':')[0])
                for name in model_names
            )
            
            if not model_found:
                print(f"❌ Model '{self.model}' not found. Available models:")
                for name in model_names:
                    print(f"   • {name}")
                print(f"💡 Install with: ollama pull {self.model}")
                return False
            
            # Test actual query
            test_response = self.query("Hello, please respond with 'Connection successful'", max_tokens=50)
            
            success = (
                "Connection successful" in test_response or
                "successful" in test_response.lower() or
                ("Hello" in test_response and "❌" not in test_response) or
                (len(test_response) > 10 and "❌" not in test_response)
            )
            
            if success:
                print(f"✅ Ollama connection successful (model: {self.model})")
            else:
                print(f"❌ Ollama test query failed: {test_response}")
            
            return success
            
        except requests.exceptions.ConnectionError:
            print(f"❌ Ollama connection failed: Is Ollama running? Start with 'ollama serve'")
            print(f"💡 Expected URL: {self.base_url}")
            return False
        except Exception as e:
            print(f"❌ Ollama connection test error: {e}")
            return False
    
    def list_available_models(self) -> list:
        """
        Get list of available models from Ollama
        
        Returns:
            List of model names
        """
        try:
            response = requests.get(self.tags_url, timeout=10)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [m['name'] for m in models]
            return []
        except:
            return []

# Simple test functionality
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ollama_client.py <model> [base_url]")
        print("Example: python ollama_client.py qwen2.5:7b")
        sys.exit(1)
    
    model = sys.argv[1]
    base_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:11434"
    
    client = OllamaClient(base_url=base_url, model=model)
    
    # Test connection
    if client.test_connection():
        # Test query
        response = client.query("Explain what cybersecurity incident response involves.", max_tokens=200)
        print(f"\nTest Response:\n{response}")
    else:
        print("\n💡 Available models:")
        models = client.list_available_models()
        for model_name in models:
            print(f"   • {model_name}")
