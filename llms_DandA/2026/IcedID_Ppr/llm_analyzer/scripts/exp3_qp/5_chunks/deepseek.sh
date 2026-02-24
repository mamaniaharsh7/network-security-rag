#!/bin/bash
# Example: Analyze security incidents using DeepSeek API

echo "🚀 Running security analysis with DeepSeek..."

# Get script directory and navigate to llm_analyzer
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/../../.." || exit 1

# Now we're in llm_analyzer/, use paths relative to here
python analyzer/modular_cli.py ../ioc_detection/query_responses/exp2_feb18 \
    --provider deepseek \
    --model deepseek-chat \
    --top-k 5 \
    --api-key-file config/keys/deepseek_key.txt \
    --cache cache/exp2_embeddings_feb18.pkl \
    --context-file config/ex1_network_context.txt \
    --questions-file config/questions_v4.txt \
    --output reports/exp3_qp/5_chunks/deepseek.md \
    --debug

echo "✅ Analysis complete! Check reports/deepseek_analysis**.md"


