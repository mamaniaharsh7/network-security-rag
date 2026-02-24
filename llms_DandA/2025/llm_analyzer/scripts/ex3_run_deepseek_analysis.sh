#!/bin/bash
# Example: Analyze security incidents using DeepSeek API

echo "🚀 Running security analysis with DeepSeek..."

python analyzer/modular_cli.py ../query_module/ex3_resp_minimal_aug7 \
    --provider deepseek \
    --model deepseek-chat \
    --api-key-file config/keys/deepseek_key.txt \
    --cache cache/ex3_security_embeddings_aug7.pkl \
    --context-file config/ex3_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/7_chunks/ex3_qv3_deepseek_analysis_aug7.md \
    --debug

echo "✅ Analysis complete! Check reports/deepseek_analysis**.md"


