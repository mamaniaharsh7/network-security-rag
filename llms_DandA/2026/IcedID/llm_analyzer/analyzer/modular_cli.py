#!/usr/bin/env python3
"""
Final Clean Multi-LLM Security Analyzer CLI
Full chunks by default, with proper argument handling
"""

import argparse
import sys
import os

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

sys.path.insert(0, current_dir)
sys.path.insert(0, parent_dir)

# Import from same directory (analyzer/)
from provider_optimized_analyzer import ProviderOptimizedAnalyzer

# Import LLM factory from llms/
sys.path.insert(0, os.path.join(parent_dir, 'llms'))
from llm_factory import LLMFactory

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Provider-Optimized Multi-LLM Security Incident Analyzer (Full Chunks Default)",
        epilog="""
Examples:
  # Analysis with full chunks (default behavior - best quality)
  %(prog)s ./data --provider ollama --model qwen2.5:7b
  %(prog)s ./data --provider cisco
  %(prog)s ./data --provider deepseek --api-key-file config/keys/deepseek_key.txt
  
  # Limit chunk size when needed (for performance)
  %(prog)s ./data --provider ollama --model qwen2.5:7b --chunk-size 500
  %(prog)s ./data --provider cisco --chunk-size 300  # Faster processing
  
  # Cache operations
  %(prog)s ./data --build-cache-only
  %(prog)s ./data --build-cache-only --cache cache/my_cache.pkl
  
  # Debug with full chunk visibility
  %(prog)s ./data --provider ollama --model deepseek-r1:8b --debug
  
  # Provider information
  %(prog)s --provider-help ollama
  %(prog)s --show-optimizations
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Positional arguments
    parser.add_argument("directory", nargs='?', help="Directory containing *_result.json files")
    
    # LLM Provider options
    parser.add_argument("--provider", choices=LLMFactory.get_available_providers(), 
                        help="LLM provider (not needed for cache-only operations)")
    parser.add_argument("--provider-help", choices=LLMFactory.get_available_providers(),
                        help="Show detailed help for specific provider and exit")
    parser.add_argument("--show-optimizations", action="store_true",
                        help="Show optimization settings for all providers and exit")
    parser.add_argument("--model", help="Model name (provider-specific)")
    
    # API key options
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--api-key", help="API key for the provider")
    key_group.add_argument("--api-key-file", help="File containing API key (e.g., config/keys/deepseek_key.txt)")
    
    # Configuration files
    parser.add_argument("--questions-file", help="File containing incident response questions")
    parser.add_argument("--context-file", help="File containing network/environment context")
    parser.add_argument("--create-questions-file", help="Create default questions file and exit")
    parser.add_argument("--create-context-file", help="Create default network context file and exit")
    parser.add_argument("--create-all-configs", help="Create all config files in specified directory and exit")
    
    # Output options
    parser.add_argument("--output", default="reports/incident_analysis.md", help="Output file")
    parser.add_argument("--cache", default="cache/security_embeddings.pkl", help="Embedding cache file")
    parser.add_argument("--rebuild-cache", action="store_true", help="Rebuild embedding cache")
    parser.add_argument("--build-cache-only", action="store_true", help="Build embeddings cache and exit (no LLM/provider needed)")
    
    # Chunk control options (NEW: full chunks by default)
    parser.add_argument("--chunk-size", type=int, help="Limit chunk size in prompts (default: full chunks for best quality)")
    
    # Processing options
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information including complete chunk content")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Handle options that don't need directory or provider FIRST
    
    if args.show_optimizations:
        print("⚡ PROVIDER OPTIMIZATION SETTINGS (Full Chunks Default)")
        print("=" * 60)
        try:
            from optimization_config import OptimizationConfig
            OptimizationConfig.print_provider_comparison()
            
            print("\n💡 NOTE: All providers now use FULL CHUNKS by default")
            print("   • Better analysis quality with complete context")
            print("   • Use --chunk-size to limit when needed for performance")
        except Exception as e:
            print(f"❌ Error: {e}")
        return
    
    if args.provider_help:
        print(f"🔍 Help for {args.provider_help.upper()}:")
        print(LLMFactory.get_provider_help(args.provider_help))
        
        print(f"\n⚡ Optimization (Full Chunks Default):")
        try:
            from optimization_config import OptimizationConfig
            recommendations = OptimizationConfig.get_provider_recommendations()
            provider_info = recommendations.get(args.provider_help, {})
            if provider_info:
                print(f"   Best for: {provider_info.get('best_for')}")
                print(f"   Strategy: {provider_info.get('description')}")
                settings = provider_info.get('settings', {})
                if settings:
                    chunks = settings.get('max_context_chunks', 'N/A')
                    chunk_size = settings.get('chunk_preview_length')
                    chunk_desc = "Full chunks" if chunk_size is None else f"{chunk_size} chars"
                    print(f"   Settings: {chunks} chunks, {chunk_desc}")
        except:
            pass
        return
    
    # Handle config creation options
    if args.create_all_configs:
        try:
            from default_configs import DefaultConfigs
            DefaultConfigs.save_default_questions_file(f"{args.create_all_configs}/questions.txt", True)
            DefaultConfigs.save_default_network_context(f"{args.create_all_configs}/network_context.txt")
            DefaultConfigs.create_api_key_templates(f"{args.create_all_configs}/keys")
            print("✅ All config files created!")
        except Exception as e:
            print(f"❌ Error: {e}")
        return
    
    if args.create_context_file:
        try:
            from default_configs import DefaultConfigs
            DefaultConfigs.save_default_network_context(args.create_context_file)
        except Exception as e:
            print(f"❌ Error: {e}")
        return
    
    if args.create_questions_file:
        try:
            from default_configs import DefaultConfigs
            DefaultConfigs.save_default_questions_file(args.create_questions_file, True)
        except Exception as e:
            print(f"❌ Error: {e}")
        return
    
    # Validate directory (needed for cache and analysis)
    if not args.directory:
        print("❌ Error: directory argument is required")
        print("\n💡 Examples:")
        print("   python analyzer/modular_cli.py ./data --build-cache-only")
        print("   python analyzer/modular_cli.py ./data --provider ollama --model qwen2.5:7b")
        print("   python analyzer/modular_cli.py --provider-help ollama")
        sys.exit(1)
    
    if not os.path.isdir(args.directory):
        print(f"❌ Directory not found: {args.directory}")
        sys.exit(1)
    
    # Handle build cache only (BEFORE provider validation)
    if args.build_cache_only:
        try:
            print("🔧 Building embeddings cache only (no LLM needed)...")
            
            # Create cache directory
            cache_dir = os.path.dirname(args.cache)
            if cache_dir and not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
                print(f"📁 Created cache directory: {cache_dir}")
            
            # Build cache using RAG directly
            from security_rag import SecurityRAG
            rag = SecurityRAG()
            
            print(f"📂 Loading documents from: {args.directory}")
            chunks_loaded = rag.load_documents(args.directory)
            
            if chunks_loaded == 0:
                print("❌ No documents found")
                print(f"💡 Check: ls {args.directory}/*_result.json")
                sys.exit(1)
            
            print(f"🧠 Building vector embeddings...")
            success = rag.build_index(args.cache, force_rebuild=True)
            
            if success:
                stats = rag.get_stats()
                print(f"✅ Cache built successfully!")
                print(f"📊 {stats['total_chunks']} chunks from {stats['files']} files")
                print(f"💾 Saved to: {args.cache}")
                
                # Show file size
                size_mb = os.path.getsize(args.cache) / (1024*1024)
                print(f"📈 Cache size: {size_mb:.1f} MB")
                
                print(f"\n🚀 Ready for analysis with full chunks:")
                print(f"   python analyzer/modular_cli.py {args.directory} --provider ollama --model qwen2.5:7b")
                return
            else:
                print("❌ Failed to build cache")
                sys.exit(1)
                
        except Exception as e:
            print(f"❌ Cache build error: {e}")
            sys.exit(1)
    
    # Validate provider (only for actual analysis)
    if not args.provider:
        print("❌ Error: --provider required for analysis")
        print(f"Available: {', '.join(LLMFactory.get_available_providers())}")
        print("\n💡 Examples:")
        print("   # Analysis with full chunks (default):")
        print("   python analyzer/modular_cli.py ./data --provider ollama --model qwen2.5:7b")
        print("   # Cache building (no provider needed):")
        print("   python analyzer/modular_cli.py ./data --build-cache-only")
        sys.exit(1)
    
    # Analysis logic
    try:
        # Prepare LLM configuration
        llm_config = {}
        
        # API providers
        if args.provider in ['deepseek', 'openai', 'anthropic']:
            if not args.api_key and not args.api_key_file:
                print(f"❌ {args.provider} requires API key")
                print(f"💡 Use: --api-key-file config/keys/{args.provider}_key.txt")
                sys.exit(1)
            
            if args.api_key:
                llm_config['api_key'] = args.api_key
            else:
                with open(args.api_key_file, 'r') as f:
                    llm_config['api_key'] = f.read().strip()
                    print(f"🔑 API key loaded from: {args.api_key_file}")
        
        # Local providers
        elif args.provider == 'ollama':
            if not args.model:
                print("❌ Ollama requires --model")
                print("💡 Example: --provider ollama --model qwen2.5:7b")
                sys.exit(1)
            llm_config['model'] = args.model
            
        elif args.provider == 'cisco':
            print("🛡️  Using Cisco Foundation-Sec-8B (local)")
            if args.model:
                llm_config['model'] = args.model
            llm_config['force_cpu'] = True  # Avoid MPS memory issues
        
        # Add model for API providers if specified
        if args.model and args.provider not in ['ollama', 'cisco']:
            llm_config['model'] = args.model
        
        # Create analyzer
        print(f"🤖 Initializing {args.provider} analyzer...")
        analyzer = ProviderOptimizedAnalyzer.from_config(args.provider, **llm_config)
        
        # Apply chunk size settings (fixed argument access)
        if hasattr(args, 'chunk_size') and args.chunk_size:
            print(f"📝 Limiting chunk size to: {args.chunk_size} characters")
            analyzer.settings['chunk_preview_length'] = args.chunk_size
        else:
            print(f"📝 Using full chunk content (no truncation)")
            analyzer.settings['chunk_preview_length'] = None  # Full chunks
        
        # Test connection
        print(f"🔌 Testing {args.provider} connection...")
        if not analyzer.llm.test_connection():
            print(f"❌ Failed to connect to {args.provider}")
            if args.provider == 'ollama':
                print("💡 Make sure Ollama is running: ollama serve")
            sys.exit(1)
        
        # Load context and questions
        if args.context_file:
            analyzer.load_network_context(args.context_file)
        else:
            analyzer.load_network_context()
        
        if args.questions_file:
            questions = analyzer.load_questions(args.questions_file)
        else:
            questions = analyzer.load_questions()
        
        # Load and index
        print(f"📂 Loading documents...")
        success = analyzer.load_and_index(args.directory, args.cache, args.rebuild_cache)
        if not success:
            print("❌ Failed to load documents")
            print(f"💡 Check: ls {args.directory}/*_result.json")
            sys.exit(1)
        
        # Run analysis
        print(f"🚀 Starting analysis with full chunk context...")
        analysis = analyzer.analyze_incident(questions, debug=args.debug)
        
        # Output results
        if args.verbose:
            print("\n" + "="*60)
            print("ANALYSIS RESULTS")
            print("="*60)
        
        print(analysis)
        
        # Save to file
        try:
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            
            with open(args.output, 'w') as f:
                f.write(analysis)
            print(f"\n📋 Analysis saved to: {args.output}")
        except Exception as e:
            print(f"❌ Error saving: {e}")
        
        print(f"✅ Analysis complete with full chunk context!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
