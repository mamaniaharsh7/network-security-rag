#!/bin/bash
# Example: Analyze security incidents using OpenAI API

echo "🚀 Running security analysis with OpenAI..."

python analyzer/modular_cli.py ../query_module/ex3_resp_minimal_aug7 \
    --provider openai \
    --model gpt-4o \
    --api-key-file config/keys/openai_key.txt \
    --cache cache/ex3_security_embeddings_aug7.pkl \
    --context-file config/ex3_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/7_chunks/ex3_qv3_openai_gpt-4o_analysis_aug7.md \
    --debug

echo "✅ Analysis complete! Check reports/openai_analysis**.md"


