#!/bin/bash
# Example: Analyze security incidents using Ollama API

echo "🚀 Running security analysis with Ollama..."


# Make sure Ollama is running
if ! curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "❌ Ollama not running. Start with: ollama serve"
    exit 1
fi

# Run analysis with qwen2.5:7b (good general model)

python analyzer/modular_cli.py ../query_module/ex2_resp_minimal_aug7 \
    --provider ollama \
    --model deepseek-r1:8b \
    --cache cache/ex2_security_embeddings_aug7.pkl \
    --context-file config/ex2_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/ex2_qv3_ollama_analysis_aug7.md \
    --debug

echo "✅ Analysis complete! Check reports/ollama_analysis**.md"


