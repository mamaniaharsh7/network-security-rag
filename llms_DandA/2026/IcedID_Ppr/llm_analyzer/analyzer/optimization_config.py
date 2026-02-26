#!/usr/bin/env python3
"""
Optimization Configuration
Provider-specific optimization settings for different LLM providers
"""

from typing import Dict, Any

class OptimizationConfig:
    """
    Configuration class for provider-specific optimizations
    """
    
    # Provider-specific optimization settings
    PROVIDER_SETTINGS = {
        # 'ollama': {
        #    'max_prompt_length': 8000,     # Aggressive for local performance
        #    'max_context_chunks': 3,       # Fewer chunks for speed
        #    'chunk_preview_length': None,  # Use full chunks by default
        #    'timeout_seconds': 300,        # 5 minute timeout
        #    'temperature': 0.1,            # Low temperature for consistency
        #    'max_tokens': 800,             # Conservative for local models
        #    'description': 'Optimized for local model performance with full chunk context',
        #    'reasoning': 'Local models get full context for better analysis, limited by chunk count for speed'
        #},
        'ollama': {
            'max_prompt_length': 12000,     # Aggressive for local performance
            'max_context_chunks': 5,       # Fewer chunks for speed
            'chunk_preview_length': None,  # Use full chunks by default
            'timeout_seconds': 300,        # 5 minute timeout
            'temperature': 0.1,            # Low temperature for consistency
            'max_tokens': 1000,             # Conservative for local models
            'description': 'Optimized for local model performance with full chunk context',
            'reasoning': 'Local models get full context for better analysis, limited by chunk count for speed'
        },        
        # 'deepseek': {
        #    'max_prompt_length': 12000,    # DeepSeek handles longer prompts well
        #    'max_context_chunks': 5,       # More context for better reasoning
        #    'chunk_preview_length': None,  # Use full chunks for reasoning
        #    'timeout_seconds': 120,        # 2 minute timeout
        #    'temperature': 0.1,            # Low for reasoning tasks
        #    'max_tokens': 1000,            # Good for reasoning responses
        #    'description': 'Full context for DeepSeek reasoning capabilities',
        #    'reasoning': 'DeepSeek excels at reasoning with complete context data'
        # },

        'deepseek': {
            'max_prompt_length': 25000,    # DeepSeek handles longer prompts well
            'max_context_chunks': 7,       # More context for better reasoning
            'chunk_preview_length': None,  # Use full chunks for reasoning
            'timeout_seconds': 300,        # 2 minute timeout
            'temperature': 0.1,            # Low for reasoning tasks
            'max_tokens': 2500,            # Good for reasoning responses
            'description': 'Full context for DeepSeek reasoning capabilities',
            'reasoning': 'DeepSeek excels at reasoning with complete context data'
        },
 
        # 'openai': {
        #    'max_prompt_length': 15000,    # GPT models handle long prompts
        #    'max_context_chunks': 5,       # Good context for quality
        #    'chunk_preview_length': None,  # Use full chunks for better analysis
        #    'timeout_seconds': 120,         # Fast API response
        #    'temperature': 0.1,            # Consistent for security analysis
        #    'max_tokens': 1200,            # Standard response length
        #    'description': 'Full context for optimal OpenAI analysis quality',
        #    'reasoning': 'GPT models perform better with complete context information'
        #},

        'openai': {
            'max_prompt_length': 25000,    # GPT models handle long prompts
            'max_context_chunks': 7,       # Good context for quality
            'chunk_preview_length': None,  # Use full chunks for better analysis
            'timeout_seconds': 120,         # Fast API response
            'temperature': 0.1,            # Consistent for security analysis
            'max_tokens': 2500,            # Standard response length
            'description': 'Full context for optimal OpenAI analysis quality',
            'reasoning': 'GPT models perform better with complete context information'
        },
        
        # 'anthropic': {
        #    'max_prompt_length': 20000,    # Claude excels with long context
        #    'max_context_chunks': 7,       # Excellent at handling more context
        #    'chunk_preview_length': None,  # Use full chunks for maximum analysis depth
        #    'timeout_seconds': 90,         # Usually fast but thorough
        #    'temperature': 0.1,            # Low for analytical tasks
        #    'max_tokens': 1500,            # Claude can handle longer responses well
        #    'description': 'Full context maximized for Claude\'s superior analysis',
        #    'reasoning': 'Claude handles complete context exceptionally well, no truncation needed'
        #},
       
        'anthropic': {
            'max_prompt_length': 25000,    # Claude excels with long context
            'max_context_chunks': 7,       # Excellent at handling more context
            'chunk_preview_length': None,  # Use full chunks for maximum analysis depth
            'timeout_seconds': 120,         # Usually fast but thorough
            'temperature': 0.1,            # Low for analytical tasks
            'max_tokens': 2500,            # Claude can handle longer responses well
            'description': 'Full context maximized for Claude\'s superior analysis',
            'reasoning': 'Claude handles complete context exceptionally well, no truncation needed'
        },
 
        'cisco': {
            'max_prompt_length': 12000,    # Good balance for security-focused local model
            'max_context_chunks': 4,       # Moderate chunks for security understanding
            'chunk_preview_length': None,  # Use full chunks for security analysis
            'timeout_seconds': 300,        # Local model can be slower on first load
            'temperature': 0.1,            # Low for security analysis consistency
            'max_tokens': 1000,            # Good length for detailed security analysis
            'description': 'Full context for Cisco\'s cybersecurity-specialized model',
            'reasoning': 'Foundation-Sec-8B benefits from complete security data context'
        }
    }
    
    @classmethod
    def get_settings(cls, provider: str) -> Dict[str, Any]:
        """
        Get optimization settings for a specific provider
        
        Args:
            provider: Provider name (case-insensitive)
            
        Returns:
            Dictionary of optimization settings
        """
        provider_lower = provider.lower()
        
        if provider_lower not in cls.PROVIDER_SETTINGS:
            # Return conservative defaults based on Ollama settings
            return cls.PROVIDER_SETTINGS['ollama'].copy()
        
        return cls.PROVIDER_SETTINGS[provider_lower].copy()
    
    @classmethod
    def get_all_providers(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get all provider settings
        
        Returns:
            Dictionary mapping provider names to their settings
        """
        return cls.PROVIDER_SETTINGS.copy()
    
    @classmethod
    def get_provider_recommendations(cls) -> Dict[str, Dict[str, str]]:
        """
        Get optimization recommendations for each provider
        
        Returns:
            Dictionary with recommendations for each provider
        """
        recommendations = {}
        
        best_for_map = {
            'ollama': 'Privacy, no internet required, free, local processing',
            'deepseek': 'Advanced reasoning, cost-effective API, step-by-step analysis',
            'openai': 'Reliable, well-documented, widely supported, consistent quality',
            'anthropic': 'Superior analysis quality, handles complex context, excellent reasoning',
            'cisco': 'Cybersecurity-specialized, local deployment, privacy-focused, threat intelligence'
        }
        
        for provider, settings in cls.PROVIDER_SETTINGS.items():
            recommendations[provider] = {
                'description': settings['description'],
                'reasoning': settings['reasoning'],
                'best_for': best_for_map[provider],
                'settings': {k: v for k, v in settings.items() 
                           if k not in ['description', 'reasoning']},
                'performance_profile': cls._get_performance_profile(provider)
            }
        
        return recommendations
    
    @classmethod
    def _get_performance_profile(cls, provider: str) -> Dict[str, str]:
        """Get performance characteristics for a provider"""
        profiles = {
            'ollama': {
                'speed': 'Variable (depends on hardware)',
                'cost': 'Free',
                'privacy': 'Excellent (local)',
                'quality': 'Good',
                'setup_complexity': 'Medium'
            },
            'deepseek': {
                'speed': 'Fast',
                'cost': 'Low',
                'privacy': 'API-dependent',
                'quality': 'Excellent (reasoning)',
                'setup_complexity': 'Low'
            },
            'openai': {
                'speed': 'Very Fast',
                'cost': 'Medium',
                'privacy': 'API-dependent',
                'quality': 'Very Good',
                'setup_complexity': 'Low'
            },
            'anthropic': {
                'speed': 'Fast',
                'cost': 'Medium-High',
                'privacy': 'API-dependent',
                'quality': 'Excellent',
                'setup_complexity': 'Low'
            },
            'cisco': {
                'speed': 'Medium-Slow (local loading)',
                'cost': 'Free (local)',
                'privacy': 'Excellent (completely local)',
                'quality': 'Excellent (security-specialized)',
                'setup_complexity': 'Medium (model download required)'
            }
        }
        
        return profiles.get(provider, {})
    
    @classmethod
    def validate_settings(cls, provider: str, custom_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and merge custom settings with provider defaults
        
        Args:
            provider: Provider name
            custom_settings: Custom optimization settings
            
        Returns:
            Validated and merged settings
        """
        default_settings = cls.get_settings(provider)
        
        # Merge custom settings with defaults
        for key, value in custom_settings.items():
            if key in default_settings:
                # Validate numeric settings
                if key in ['max_prompt_length', 'max_context_chunks', 'chunk_preview_length', 'timeout_seconds', 'max_tokens']:
                    if isinstance(value, (int, float)) and value > 0:
                        default_settings[key] = value
                    else:
                        print(f"⚠️  Invalid {key}: {value}, using default: {default_settings[key]}")
                
                # Validate temperature
                elif key == 'temperature':
                    if isinstance(value, (int, float)) and 0.0 <= value <= 2.0:
                        default_settings[key] = value
                    else:
                        print(f"⚠️  Invalid temperature: {value}, using default: {default_settings[key]}")
                
                # Allow other settings to pass through
                else:
                    default_settings[key] = value
        
        return default_settings
    
    @classmethod
    def print_provider_comparison(cls):
        """Print a comparison table of all providers"""
        print("\n📊 PROVIDER OPTIMIZATION COMPARISON")
        print("=" * 80)
        
        headers = ["Provider", "Chunks", "Prompt Len", "Preview", "Tokens", "Speed Focus"]
        
        # Print header
        print(f"{'Provider':<12} {'Chunks':<8} {'Prompt':<10} {'Preview':<8} {'Tokens':<8} {'Description':<30}")
        print("-" * 80)
        
        # Print each provider
        for provider, settings in cls.PROVIDER_SETTINGS.items():
            print(f"{provider:<12} "
                  f"{settings['max_context_chunks']:<8} "
                  f"{settings['max_prompt_length']:<10} "
                  f"{settings['chunk_preview_length']:<8} "
                  f"{settings['max_tokens']:<8} "
                  f"{settings['description']:<30}")

# Simple test functionality
if __name__ == "__main__":
    print("🔧 Optimization Configuration Test")
    print("=" * 40)
    
    # Test getting settings for each provider
    for provider in ['ollama', 'deepseek', 'openai', 'anthropic']:
        settings = OptimizationConfig.get_settings(provider)
        print(f"\n{provider.upper()} Settings:")
        for key, value in settings.items():
            print(f"  {key}: {value}")
    
    # Test provider comparison
    OptimizationConfig.print_provider_comparison()
    
    # Test recommendations
    print("\n📋 Provider Recommendations:")
    recommendations = OptimizationConfig.get_provider_recommendations()
    for provider, info in recommendations.items():
        print(f"\n{provider.upper()}:")
        print(f"  Best for: {info['best_for']}")
        print(f"  Reasoning: {info['reasoning']}")
        
        profile = info['performance_profile']
        if profile:
            print(f"  Performance: Speed={profile.get('speed', 'N/A')}, Cost={profile.get('cost', 'N/A')}, Quality={profile.get('quality', 'N/A')}")
