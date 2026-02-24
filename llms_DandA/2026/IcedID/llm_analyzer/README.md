# 🛡️ Multi-LLM Security Incident Analyzer

A clean, provider-optimized security incident analysis framework supporting multiple LLM providers with RAG (Retrieval-Augmented Generation).

## 🚀 Quick Start

### Step 1: Setup and Configuration

#### 📊 Test Optimization Settings
```bash
# View provider-specific optimizations
python analyzer/optimization_config.py

# Show detailed provider help
python analyzer/modular_cli.py --provider-help ollama
python analyzer/modular_cli.py --provider-help deepseek
python analyzer/modular_cli.py --provider-help openai

# Create all configuration files at once
python analyzer/modular_cli.py --create-all-configs config
```

#### 📦 Install Dependencies
```bash
pip install -r requirements.txt
```

#### 🤖 Configure LLM Provider

**Option A: Ollama (Local, Free, Private)**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve

# Install recommended model
ollama pull qwen2.5:7b
```

**Option B: API-based Providers**
```bash
# DeepSeek API key
echo "your-deepseek-api-key-here" > config/keys/deepseek_key.txt

# OpenAI API key  
echo "your-openai-api-key-here" > config/keys/openai_key.txt

# Anthropic API key
echo "your-anthropic-api-key-here" > config/keys/anthropic_key.txt
```

### Step 2: Build Embeddings Cache

Build the vector embeddings cache first for faster analysis:

```bash
# Build cache only (no LLM analysis needed)
python analyzer/modular_cli.py ./data --build-cache-only --cache cache/security_embeddings.pkl

# Or rebuild existing cache
python analyzer/modular_cli.py ./data --build-cache-only --rebuild-cache
```

**What the Cache Contains:**
- Document chunks from your `./data/*_result.json` files
- Vector embeddings for semantic search
- Metadata (filenames, sections, importance scores)

> 💡 **Building the cache first helps validate your data and speeds up all future analyses!**

### Step 3: Run Security Analysis

#### 🔍 Direct Analysis Commands

**Ollama (Local)**
```bash
python analyzer/modular_cli.py ./data --provider ollama --model qwen2.5:7b
```

**DeepSeek (API)**
```bash
python analyzer/modular_cli.py ./data --provider deepseek --api-key-file config/keys/deepseek_key.txt
```

**OpenAI (API)**
```bash
python analyzer/modular_cli.py ./data --provider openai --api-key-file config/keys/openai_key.txt --model gpt-4
```

**Anthropic (API)**
```bash
python analyzer/modular_cli.py ./data --provider anthropic --api-key-file config/keys/anthropic_key.txt
```

#### 📜 Using Helper Scripts

```bash
# Ollama analysis script
sh scripts/run_ollama_analysis.sh

# DeepSeek analysis script  
sh scripts/run_deepseek_analysis.sh

# OpenAI analysis script
sh scripts/run_openai_analysis.sh
```

## 📁 Project Structure

```
security-analyzer/
├── analyzer/                           # 🎯 All analyzer code
│   ├── security_rag.py               # RAG system
│   ├── provider_optimized_analyzer.py # Clean analysis pipeline
│   ├── optimization_config.py         # Provider optimization settings
│   ├── default_configs.py            # Default questions/context generator
│   ├── prompt_templates.py           # Clean prompt building
│   └── modular_cli.py                # CLI interface
├── llms/                              # 🤖 LLM client modules
│   ├── base_llm_client.py
│   ├── deepseek_client.py
│   ├── ollama_client.py
│   ├── openai_client.py
│   ├── anthropic_client.py
│   └── llm_factory.py
├── config/                            # ⚙️ Configuration
│   ├── keys/                          # 🔑 API keys
│   │   ├── deepseek_key.txt
│   │   ├── openai_key.txt
│   │   └── anthropic_key.txt
│   ├── questions.txt                  # Incident response questions
│   ├── network_context.txt           # Network environment context
│   └── llm_config.json              # LLM provider settings
├── data/                              # 📂 Input data
│   └── *_result.json                 # Security query result files
├── reports/                           # 📊 Output reports
│   └── incident_analysis.md
├── cache/                             # 💾 Embeddings cache
│   └── security_embeddings.pkl
└── scripts/                           # 🔧 Helper scripts
    ├── run_ollama_analysis.sh
    └── run_deepseek_analysis.sh
```

## 🤖 Supported LLM Providers

| Provider | Type | Best For | Setup |
|----------|------|----------|-------|
| **Ollama** | Local | Privacy, no cost, offline | `ollama pull qwen2.5:7b` |
| **DeepSeek** | API | Advanced reasoning, cost-effective | API key required |
| **OpenAI** | API | Reliable, well-documented | API key required |
| **Anthropic** | API | Superior analysis quality | API key required |

## ⚡ Provider-Specific Optimizations

The analyzer automatically optimizes prompts and settings for each provider:

- **Ollama**: Shorter prompts for faster local processing
- **DeepSeek**: Balanced for reasoning capabilities
- **OpenAI**: Cost/quality optimization
- **Anthropic**: Maximized context for superior analysis

View all optimizations:
```bash
python analyzer/modular_cli.py --show-optimizations
```

## 🔧 Configuration

### Default Questions
The analyzer comes with default incident response questions, or you can customize:

```bash
# Create custom questions file
python analyzer/modular_cli.py --create-questions-file config/questions.txt
# Then edit config/questions.txt
```

### Network Context
Provide your network environment details for better analysis:

```bash
# Create network context template
python analyzer/modular_cli.py --create-context-file config/network_context.txt
# Then edit config/network_context.txt with your network details
```

## 🧪 Testing

```bash
# Test individual components
python analyzer/optimization_config.py        # Test optimization settings
python analyzer/default_configs.py questions  # Show default questions
python analyzer/prompt_templates.py          # Test prompt building

# Test LLM connections
python analyzer/modular_cli.py --provider-help ollama

# Test full analysis with debug
python analyzer/modular_cli.py ./data --provider ollama --model qwen2.5:7b --debug
```

## 📋 Example Usage

```python
# Python API usage
from analyzer import ProviderOptimizedAnalyzer

# Create analyzer
analyzer = ProviderOptimizedAnalyzer.from_config('ollama', model='qwen2.5:7b')

# Load and analyze
analyzer.load_and_index('./data')
analyzer.load_questions('config/questions.txt')  # or None for defaults
analyzer.load_network_context('config/network_context.txt')

# Run analysis
report = analyzer.analyze_incident(debug=False)

# Save results
with open('reports/analysis.md', 'w') as f:
    f.write(report)
```

## 🎯 Performance

The clean architecture provides significant performance improvements:

- **77% shorter prompts** (3k vs 13k characters)
- **85% faster responses** (30 seconds vs 10 minutes)
- **Provider-optimized settings** for best performance/quality balance

## 📚 Features

- ✅ **Multi-LLM Support**: Ollama, DeepSeek, OpenAI, Anthropic
- ✅ **Provider Optimization**: Automatic settings per provider
- ✅ **RAG-based Analysis**: Semantic search through security logs
- ✅ **Clean Architecture**: Separated concerns, easy to maintain
- ✅ **Flexible Configuration**: Custom questions, network context
- ✅ **Cache System**: Fast embeddings cache for repeated analysis
- ✅ **Privacy Options**: Local Ollama models or cloud APIs

## 🤝 Contributing

The modular architecture makes it easy to add new LLM providers:

1. Create new client in `llms/`
2. Register in `llms/llm_factory.py`
3. Add optimization settings in `analyzer/optimization_config.py`

## 📄 License

This project provides a framework for security incident analysis using various LLM providers. Ensure compliance with your organization's security and data handling policies.
