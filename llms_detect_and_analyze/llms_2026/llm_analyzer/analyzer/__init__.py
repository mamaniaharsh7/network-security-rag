"""
Security Analyzer Package
Clean, modular security incident analysis with multi-LLM support
"""

# Core analysis components
from .security_rag import SecurityRAG
from .provider_optimized_analyzer import ProviderOptimizedAnalyzer

# Configuration and utilities
from .optimization_config import OptimizationConfig
from .default_configs import DefaultConfigs
from .prompt_templates import PromptTemplates

# Main exports for external use
__all__ = [
    # Core analysis
    'SecurityRAG',
    'ProviderOptimizedAnalyzer',
    
    # Configuration utilities
    'OptimizationConfig', 
    'DefaultConfigs',
    'PromptTemplates'
]



