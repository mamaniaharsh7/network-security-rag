#!/bin/bash
# Example: Analyze security incidents using OpenAI API

echo "🚀 Running security analysis with OpenAI..."

python analyzer/modular_cli.py ../query_module/ex2_resp_minimal_aug7 \
    --provider openai \
    --model gpt-4o \
    --api-key-file config/keys/openai_key.txt \
    --cache cache/ex2_security_embeddings_aug7.pkl \
    --context-file config/ex2_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/7_chunks/ex2_qv3_openai_gpt-4o_analysis_aug7.md \
    --debug

echo "✅ Analysis complete! Check reports/openai_analysis**.md"


