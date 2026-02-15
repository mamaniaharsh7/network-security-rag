#!/usr/bin/env python3
"""
Anthropic LLM Client
Implementation for Anthropic Claude API
"""

import requests
from typing import Optional
from base_llm_client import BaseLLMClient

class AnthropicClient(BaseLLMClient):
    """
    Anthropic Claude API client
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com/v1/messages", **kwargs):
        """
        Initialize Anthropic client
        
        Args:
            api_key: Anthropic API key
            base_url: API endpoint URL
            **kwargs: Additional configuration
        """
        super().__init__(api_key=api_key, base_url=base_url, **kwargs)
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        print(f"🔮 Anthropic Claude client initialized")
        print(f"🔗 Endpoint: {base_url}")
        print(f"📋 API version: 2023-06-01")
    
    def query(self, prompt: str, model: str = "claude-sonnet-4-20250514", max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        """
        Send query to Anthropic API
        
        Args:
            prompt: The prompt to send
            model: Model name to use (updated for Claude 4)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            **kwargs: Additional API parameters
            
        Returns:
            API response text or error message
        """
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        # Add any additional parameters
        payload.update(kwargs)
        
        try:
            print(f"🔮 Sending request to Anthropic...")
            print(f"📋 Model: {model}")
            print(f"🔗 URL: {self.base_url}")
            
            response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=120)
            
            print(f"📊 Response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                return result['content'][0]['text']
            elif response.status_code == 404:
                return f"❌ Model '{model}' not found. Try: claude-3-5-sonnet-20241022 or claude-3-opus-20240229"
            elif response.status_code == 401:
                return "❌ Invalid API key. Check your Anthropic API key."
            elif response.status_code == 429:
                return "❌ Rate limit exceeded. Wait and try again."
            else:
                error_text = response.text
                return f"❌ Anthropic API Error: {response.status_code} - {error_text}"
            
        except requests.exceptions.Timeout:
            return "❌ Anthropic Timeout: Request took too long"
        except requests.exceptions.RequestException as e:
            return f"❌ Anthropic API Error: {e}"
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
        print(f"🔮 Testing Anthropic connection...")
        print(f"🔗 Endpoint: {self.base_url}")
        
        # Try with the model specified in query() default
        test_prompt = "Hello, please respond with 'Connection successful'"
        response = self.query(test_prompt, max_tokens=50)
        
        success = (
            "Connection successful" in response or 
            "successful" in response.lower() or
            ("Hello" in response and "❌" not in response) or
            (len(response) > 10 and "❌" not in response)
        )
        
        if success:
            print("✅ Anthropic API connection successful")
        else:
            print(f"❌ Anthropic API connection failed: {response}")
            
            # Provide helpful debugging info
            if "not found" in response.lower() or "404" in response:
                print(f"💡 Model may not exist. Try these known working models:")
                print(f"   --model claude-3-5-sonnet-20241022")
                print(f"   --model claude-3-opus-20240229") 
                print(f"   --model claude-3-haiku-20240307")
            elif "401" in response or "invalid" in response.lower():
                print(f"💡 Check your API key:")
                print(f"   1. Get key from: https://console.anthropic.com/")
                print(f"   2. Save to: config/keys/anthropic_key.txt")
        
        return success

# Simple test functionality
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python anthropic_client.py <api_key>")
        sys.exit(1)
    
    client = AnthropicClient(sys.argv[1])
    
    # Test connection
    if client.test_connection():
        # Test analysis
        response = client.query("Analyze the key components of a cybersecurity incident response plan.", max_tokens=300)
        print(f"\nTest Response:\n{response}")
