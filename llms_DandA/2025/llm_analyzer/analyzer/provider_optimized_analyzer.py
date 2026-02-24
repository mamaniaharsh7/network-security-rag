#!/usr/bin/env python3
"""
Ultra-Clean Provider-Optimized Security Incident Analyzer
Minimal, focused analysis pipeline with clean prompts
"""

import os
import sys
from typing import List, Dict

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

sys.path.insert(0, current_dir)
sys.path.insert(0, parent_dir)

# Import dependencies
from security_rag import SecurityRAG
from optimization_config import OptimizationConfig
from default_configs import DefaultConfigs
from prompt_templates import PromptTemplates

# Import from llms directory
llms_dir = os.path.join(parent_dir, 'llms')
sys.path.insert(0, llms_dir)
from base_llm_client import BaseLLMClient
from llm_factory import LLMFactory

class ProviderOptimizedAnalyzer:
    """
    Ultra-clean security incident analyzer focused purely on analysis pipeline
    All configuration, defaults, and prompt building externalized
    """
    
    def __init__(self, llm_client: BaseLLMClient, custom_settings: Dict = None):
        """
        Initialize analyzer with clean, optimized settings
        
        Args:
            llm_client: LLM client implementing BaseLLMClient
            custom_settings: Optional custom optimization settings
        """
        self.rag = SecurityRAG()
        self.llm = llm_client
        self.questions = []
        self.network_context = ""
        
        # Load optimization settings (externalized)
        provider_name = self.llm.get_provider_name().lower()
        
        if custom_settings:
            self.settings = OptimizationConfig.validate_settings(provider_name, custom_settings)
        else:
            self.settings = OptimizationConfig.get_settings(provider_name)
        
        print(f"🤖 {self.llm.get_provider_name()} analyzer initialized")
        print(f"⚡ {self.settings['description']}")
    
    @classmethod
    def from_config(cls, provider: str, custom_settings: Dict = None, **llm_config):
        """Create analyzer from provider configuration"""
        llm_client = LLMFactory.create_client(provider, **llm_config)
        return cls(llm_client, custom_settings)
    
    def load_and_index(self, directory: str, cache_file: str = "cache/security_embeddings.pkl", 
                      rebuild_cache: bool = False) -> bool:
        """Load and index security documents"""
        print(f"📂 Loading from: {directory}")
        
        chunks_loaded = self.rag.load_documents(directory)
        if chunks_loaded == 0:
            return False
        
        # Ensure cache directory exists
        cache_dir = os.path.dirname(cache_file)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
        
        success = self.rag.build_index(cache_file, force_rebuild=rebuild_cache)
        
        if success:
            stats = self.rag.get_stats()
            print(f"📊 Ready: {stats['total_chunks']} chunks from {stats['files']} files")
        
        return success
    
    def load_questions(self, questions_file: str = None) -> List[str]:
        """Load questions (uses external default generator)"""
        if questions_file:
            self.questions = DefaultConfigs.load_questions_from_file(questions_file)
        else:
            self.questions = DefaultConfigs.get_default_questions()
            print(f"📋 Using {len(self.questions)} default questions")
        
        return self.questions
    
    def load_network_context(self, context_file: str = None) -> str:
        """Load network context (uses external default generator)"""
        if context_file:
            self.network_context = DefaultConfigs.load_network_context_from_file(context_file)
        else:
            self.network_context = DefaultConfigs.get_minimal_network_context()
            print("🌐 Using minimal default network context")
        
        return self.network_context
    
    def analyze_question(self, question: str, debug: bool = False) -> str:
        """
        Analyze a single incident response question
        
        Args:
            question: The question to analyze
            debug: Show debug information including RAG search details
            
        Returns:
            Analysis result
        """
        relevant_chunks = self.rag.search(question, top_k=self.settings['max_context_chunks'])
        
        if not relevant_chunks:
            return "Not found in provided data"
        
        if debug:
            print(f"\n🔍 DEBUG: {self.llm.get_provider_name()} analyzing: {question}")
            print(f"📊 RAG Search Results: Found {len(relevant_chunks)} relevant chunks")
            print("=" * 80)
            
            for i, (text, score, meta) in enumerate(relevant_chunks, 1):
                print(f"CHUNK {i}:")
                print(f"  📄 File: {meta['filename']}")
                print(f"  📍 Section: {meta['section']}")
                print(f"  📊 Relevance Score: {score:.4f}")
                print(f"  📋 Type: {meta.get('type', 'unknown')}")
                print(f"  ⭐ Importance: {meta.get('importance', 'medium')}")
                print(f"  📝 FULL CONTENT:")
                print("-" * 40)
                print(text)
                print("-" * 40)
                print(f"  📏 Content Length: {len(text)} characters")
                print(f"  📖 Word Count: {len(text.split())} words")
                print()
            
            print("=" * 80)
        
        # Build provider-optimized prompt (pass chunk_preview_length, None = full chunks)
        prompt = PromptTemplates.build_analysis_prompt(
            question, 
            relevant_chunks, 
            self.network_context, 
            self.settings['max_prompt_length'],
            self.settings.get('chunk_preview_length')  # None = full chunks (new default)
        )
        
        if debug:
            stats = PromptTemplates.get_prompt_stats(prompt)
            print(f"📝 Prompt Statistics:")
            print(f"  📏 Total length: {stats['total_length']} characters")
            print(f"  📄 Lines: {stats['lines']}")
            print(f"  📖 Words: {stats['words']}")
            print(f"  🎯 Estimated tokens: ~{int(stats['estimated_tokens'])}")
            print(f"  🎛️  Max allowed: {self.settings['max_prompt_length']} characters")
            
            print(f"\n📝 FULL PROMPT BEING SENT:")
            print("=" * 80)
            print(prompt)
            print("=" * 80)
            
            print(f"🎯 Sending to {self.llm.get_provider_name()}...")
            print("⏳ Waiting for response...")
            print("-" * 80)
        
        # Query LLM
        try:
            response = self.llm.query(
                prompt, 
                max_tokens=self.settings['max_tokens'], 
                temperature=self.settings['temperature']
            )
            
            if debug:
                print(f"✅ Response received from {self.llm.get_provider_name()}:")
                print(f"  📏 Response length: {len(response)} characters")
                print(f"  📖 Word count: {len(response.split())} words")
                print(f"  🎯 Max tokens allowed: {self.settings['max_tokens']}")
                
                # Show response preview
                print(f"📋 Response Preview:")
                print(f"  {response[:300]}{'...' if len(response) > 300 else ''}")
                print("-" * 60)
            
            return response.strip()
            
        except Exception as e:
            error_msg = f"Error querying {self.llm.get_provider_name()}: {e}"
            if debug:
                print(f"❌ {error_msg}")
            return f"❌ {error_msg}"
    
    def analyze_incident(self, custom_questions: List[str] = None, debug: bool = False) -> str:
        """
        Analyze complete incident with detailed debug information and timing
        
        Args:
            custom_questions: Optional custom questions
            debug: Show detailed debug information including RAG search results
            
        Returns:
            Complete analysis report with timing information
        """
        import time
        
        # Start timing
        start_time = time.time()
        
        questions = custom_questions or self.questions or DefaultConfigs.get_default_questions()
        
        print(f"🚀 Starting analysis with {self.llm.get_provider_name()}")
        
        if debug:
            print(f"🔍 DEBUG MODE ENABLED")
            print(f"📊 Analysis Configuration:")
            print(f"  Provider: {self.llm.get_provider_name()}")
            print(f"  Questions: {len(questions)}")
            print(f"  Max chunks per question: {self.settings['max_context_chunks']}")
            print(f"  Max prompt length: {self.settings['max_prompt_length']}")
            
            # Fix f-string syntax issue
            chunk_setting = self.settings.get('chunk_preview_length')
            if chunk_setting is None:
                chunk_desc = "Full chunks"
            else:
                chunk_desc = f"{chunk_setting} chars"
            print(f"  Chunk preview length: {chunk_desc}")
            
            print(f"  Temperature: {self.settings['temperature']}")
            print(f"  Max tokens: {self.settings['max_tokens']}")
            
            # Show RAG statistics
            rag_stats = self.rag.get_stats()
            print(f"📚 RAG Database:")
            print(f"  Total chunks: {rag_stats['total_chunks']}")
            print(f"  Files processed: {rag_stats['files']}")
            print(f"  Chunk types: {rag_stats['chunk_types']}")
            print("=" * 80)
        
        # Track question timing
        question_times = []
        
        # Analyze each question
        results = []
        for i, question in enumerate(questions, 1):
            question_start = time.time()
            print(f"📋 Question {i}/{len(questions)}: {question}")
            
            try:
                answer = self.analyze_question(question, debug=debug)
                results.append(f"**{i}. {question}**\n{answer}")
                
                question_duration = time.time() - question_start
                question_times.append(question_duration)
                
                print(f"✅ Question {i} completed ({question_duration:.1f}s)")
                
                if debug:
                    print(f"=" * 80)
                    
            except Exception as e:
                error_msg = f"Error analyzing question {i}: {e}"
                print(f"❌ {error_msg}")
                results.append(f"**{i}. {question}**\n{error_msg}")
                question_times.append(0)  # Record 0 for failed questions
        
        # Generate summary with timing
        summary_start = time.time()
        if not debug and results:
            print("📝 Generating summary...")
            summary = self._generate_summary(results)
        else:
            if debug:
                print("📝 Generating summary (debug mode)...")
                summary = self._generate_summary(results)
                print(f"📋 Summary generated: {len(summary)} characters")
            else:
                summary = "Summary skipped"
        summary_duration = time.time() - summary_start
        
        # Calculate total time and statistics
        total_duration = time.time() - start_time
        avg_question_time = sum(question_times) / len(question_times) if question_times else 0
        
        # Build final report with timing
        stats = self.rag.get_stats()
        
        # Fix f-string syntax for chunk context description
        chunk_setting = self.settings.get('chunk_preview_length')
        if chunk_setting is None:
            chunk_context_desc = "Full chunks"
        else:
            chunk_context_desc = f"{chunk_setting} chars"
        
        report = f"""# SECURITY INCIDENT ANALYSIS

## FINDINGS

{chr(10).join(results)}

## SUMMARY

{summary}

## METADATA

- **Provider:** {self.llm.get_provider_name()}
- **Optimization:** {self.settings['description']}
- **Data:** {stats['files']} files, {stats['total_chunks']} chunks
- **Settings:** {self.settings['max_context_chunks']} chunks/question
- **Chunk Context:** {chunk_context_desc}
- **Analysis Date:** {self._get_timestamp()}
- **Analysis Duration:** {self._format_duration(total_duration)}
- **Questions Processed:** {len(questions)}
- **Average Time per Question:** {avg_question_time:.1f}s
- **Summary Generation Time:** {summary_duration:.1f}s
- **Performance:** {len(questions) / total_duration * 60:.1f} questions/minute

## TIMING BREAKDOWN

{self._format_timing_breakdown(questions, question_times)}

---
*Generated by Ultra-Clean Security Analyzer*
"""
        
        if debug:
            print(f"\n📊 FINAL TIMING STATISTICS:")
            print(f"  ⏱️  Total analysis time: {self._format_duration(total_duration)}")
            print(f"  📋 Questions processed: {len(questions)}")
            print(f"  ⚡ Average per question: {avg_question_time:.1f}s")
            print(f"  📝 Summary generation: {summary_duration:.1f}s")
            print(f"  🚀 Performance: {len(questions) / total_duration * 60:.1f} questions/minute")
            print(f"  📄 Total report length: {len(report)} characters")
            print("=" * 80)
        
        return report
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            remaining_seconds = seconds % 60
            return f"{minutes}m {remaining_seconds:.1f}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            remaining_seconds = seconds % 60
            return f"{hours}h {minutes}m {remaining_seconds:.1f}s"
    
    def _format_timing_breakdown(self, questions: List[str], question_times: List[float]) -> str:
        """Format detailed timing breakdown"""
        breakdown = []
        for i, (question, duration) in enumerate(zip(questions, question_times), 1):
            if duration > 0:
                breakdown.append(f"- **Question {i}:** {duration:.1f}s - {question}")
            else:
                breakdown.append(f"- **Question {i}:** Failed - {question}")
        
        return "\n".join(breakdown)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for report"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _generate_summary(self, results: List[str]) -> str:
        """Generate clean summary"""
        results_text = "\n".join(results)
        
        # Use clean summary prompt (externalized)
        summary_prompt = PromptTemplates.build_summary_prompt(results_text)
        
        try:
            return self.llm.query(summary_prompt, max_tokens=300, temperature=0.1)
        except Exception as e:
            return f"Summary generation failed: {e}"
    
    # Clean info methods
    def get_optimization_info(self) -> Dict:
        """Get optimization information"""
        return {
            "current_provider": self.llm.get_provider_name(),
            "current_settings": self.settings,
            "all_provider_recommendations": OptimizationConfig.get_provider_recommendations()
        }
    
    def get_llm_info(self) -> Dict:
        """Get LLM information"""
        return {
            "provider": self.llm.get_provider_name(),
            "config": self.llm.get_config(),
            "optimization": self.settings
        }

# Clean test functionality
if __name__ == "__main__":
    import sys
    
    print("🧪 Ultra-Clean Security Analyzer Test")
    print("🎯 Minimal prompts, focused pipeline")
    print("=" * 45)
    
    if len(sys.argv) == 1:
        print("\n⚡ Optimization Settings:")
        OptimizationConfig.print_provider_comparison()
        
        print(f"\nUsage:")
        print(f"  python analyzer/provider_optimized_analyzer.py ollama ./data qwen2.5:7b")
        print(f"  python analyzer/provider_optimized_analyzer.py deepseek ./data <api_key>")
        sys.exit(0)
    
    if len(sys.argv) >= 3:
        provider = sys.argv[1]
        directory = sys.argv[2]
        
        try:
            if provider == "ollama":
                model = sys.argv[3] if len(sys.argv) > 3 else "qwen2.5:7b"
                analyzer = ProviderOptimizedAnalyzer.from_config("ollama", model=model)
            elif provider == "deepseek":
                if len(sys.argv) < 4:
                    print("Usage: python analyzer/provider_optimized_analyzer.py deepseek ./data <api_key>")
                    sys.exit(1)
                analyzer = ProviderOptimizedAnalyzer.from_config("deepseek", api_key=sys.argv[3])
            else:
                print(f"Provider '{provider}' not implemented in test")
                sys.exit(1)
            
            # Test connection
            if analyzer.llm.test_connection():
                # Load data
                success = analyzer.load_and_index(directory)
                if success:
                    # Load questions and context
                    analyzer.load_questions()
                    analyzer.load_network_context()
                    
                    # Run analysis on first 2 questions
                    questions = analyzer.questions[:2]
                    result = analyzer.analyze_incident(questions, debug=True)
                    print(result)
                else:
                    print("❌ Failed to load documents")
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
    else:
        print("Usage: python analyzer/provider_optimized_analyzer.py <provider> <directory> [api_key_or_model]")
