#!/bin/bash
# Example: Analyze security incidents using Anthropic API

echo "🚀 Running security analysis with Anthropic..."

python analyzer/modular_cli.py ../query_module/ex3_resp_minimal_aug7 \
    --provider anthropic \
    --model claude-sonnet-4-20250514 \
    --api-key-file config/keys/anthropic_key.txt \
    --cache cache/ex3_security_embeddings_aug7.pkl \
    --context-file config/ex3_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/ex3_qv3_anthropic_analysis_aug7.md \
    --debug

echo "✅ Analysis complete! Check reports/anthropic_analysis**.md"


