#!/usr/bin/env python3
"""
DeepSeek LLM Client
Implementation for DeepSeek API
"""

import requests
from typing import Optional
from base_llm_client import BaseLLMClient

class DeepSeekClient(BaseLLMClient):
    """
    DeepSeek API client for LLM queries
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com/v1/chat/completions", **kwargs):
        """
        Initialize DeepSeek client
        
        Args:
            api_key: DeepSeek API key
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
    
    def query(self, prompt: str, model: str = "deepseek-chat", max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        """
        Send query to DeepSeek API
        
        Args:
            prompt: The prompt to send
            model: Model name to use
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative)
            **kwargs: Additional API parameters
            
        Returns:
            API response text or error message
        """
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False
        }
        
        # Add any additional parameters
        payload.update(kwargs)
        
        try:
            response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            message = result['choices'][0]['message']
            
            # Handle DeepSeek Reasoner format (has reasoning_content)
            if 'reasoning_content' in message and message['reasoning_content']:
                return message['reasoning_content']
            elif 'content' in message:
                return message['content']
            else:
                return "❌ No content in response"
            
        except requests.exceptions.Timeout:
            return "❌ API Timeout: Request took too long"
        except requests.exceptions.RequestException as e:
            return f"❌ API Error: {e}"
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
        
        # Check for success indicators
        success = (
            "Connection successful" in response or 
            "successful" in response.lower() or
            ("Hello" in response and "❌" not in response) or
            (len(response) > 10 and "❌" not in response)  # Any reasonable response
        )
        
        if success:
            print("✅ DeepSeek API connection successful")
        else:
            print(f"❌ DeepSeek API connection failed: {response}")
        
        return success

# Simple test functionality
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python deepseek_client.py <api_key>")
        sys.exit(1)
    
    client = DeepSeekClient(sys.argv[1])
    
    # Test connection
    if client.test_connection():
        # Test reasoning
        response = client.query("What is 2+2? Explain your reasoning.", max_tokens=200)
        print(f"\nTest Response:\n{response}")
