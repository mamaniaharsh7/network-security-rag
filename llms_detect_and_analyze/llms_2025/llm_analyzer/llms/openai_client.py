#!/usr/bin/env python3
"""
OpenAI LLM Client
Implementation for OpenAI API
"""

import requests
from typing import Optional
from base_llm_client import BaseLLMClient

class OpenAIClient(BaseLLMClient):
    """
    OpenAI API client for GPT models
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1/chat/completions", **kwargs):
        """
        Initialize OpenAI client
        
        Args:
            api_key: OpenAI API key
            base_url: API endpoint URL
            **kwargs: Additional configuration
        """
        super().__init__(api_key=api_key, base_url=base_url, **kwargs)
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def query(self, prompt: str, model: str = "gpt-3.5-turbo", max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        """
        Send query to OpenAI API
        
        Args:
            prompt: The prompt to send
            model: Model name to use (gpt-3.5-turbo, gpt-4, etc.)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            **kwargs: Additional API parameters
            
        Returns:
            API response text or error message
        """
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        # Add any additional parameters
        payload.update(kwargs)
        
        try:
            response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            return result['choices'][0]['message']['content']
            
        except requests.exceptions.Timeout:
            return "❌ OpenAI Timeout: Request took too long"
        except requests.exceptions.RequestException as e:
            return f"❌ OpenAI API Error: {e}"
        except KeyError as e:
            return f"❌ Response parsing error: {e}"
        except Exception as e:
            return f"❌ Unexpected error: {e}"
    
    def test_connection(self) -> bool:
        """
        Test if API key and connection work
        
        Returns:
            True if connection successful
        """
        test_prompt = "Hello, please respond with 'Connection successful'"
        response = self.query(test_prompt, max_tokens=50)
        
        success = (
            "Connection successful" in response or 
            "successful" in response.lower() or
            ("Hello" in response and "❌" not in response) or
            (len(response) > 10 and "❌" not in response)
        )
        
        if success:
            print("✅ OpenAI API connection successful")
        else:
            print(f"❌ OpenAI API connection failed: {response}")
        
        return success

# Simple test functionality
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python openai_client.py <api_key>")
        sys.exit(1)
    
    client = OpenAIClient(sys.argv[1])
    
    # Test connection
    if client.test_connection():
        # Test reasoning
        response = client.query("What are the key steps in cybersecurity incident response?", max_tokens=300)
        print(f"\nTest Response:\n{response}")
