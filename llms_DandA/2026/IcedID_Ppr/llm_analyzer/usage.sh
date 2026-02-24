# Step 1: Setup

# Test optimization settings
python analyzer/optimization_config.py

# Show provider help
python analyzer/modular_cli.py --provider-help ollama
python analyzer/modular_cli.py --provider-help deepseek
python analyzer/modular_cli.py --provider-help openai

# Create all config files at once
python analyzer/modular_cli.py --create-all-configs config

# Install dependencies
pip install -r requirements.txt

# Configure LLM provider

# Option A. Ollama - Local, free

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve

# Install recommended model
ollama pull qwen2.5:7b

# Option B. API-based Providers

# Save your API key
echo "your-api-key-here" > keys/deepseek_key.txt
# OR
echo "your-api-key-here" > keys/openai_key.txt


# Step 2: Build cache only (no LLM analysis)
python analyzer/modular_cli.py ./data --build-cache-only --cache cache/security_embeddings.pkl

# Or rebuild existing cache
python analyzer/modular_cli.py ./data --build-cache-only --rebuild-cache

What the Cache Contains:

- Document chunks from the ./data/*_result.json files
- Vector embeddings for semantic search
- Metadata (filenames, sections, importance scores)

Building the cache first helps validate our data and speeds up all future analyses

# Step 3: Run Analysis

# Using Ollama (recommended for privacy)
sh scripts/run_ollama_analysis.sh

# Using DeepSeek
sh scripts/run_deepseek_analysis.sh

# Using OpenAI
sh scripts/run_openai_analysis.sh


