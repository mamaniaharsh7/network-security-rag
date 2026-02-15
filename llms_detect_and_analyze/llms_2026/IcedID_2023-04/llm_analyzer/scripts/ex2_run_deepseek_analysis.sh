#!/bin/bash
# Run from llm_analyzer/ directory

echo "🚀 Running security analysis with DeepSeek..."

# Get script directory and navigate to llm_analyzer
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# Now we're in llm_analyzer/, use paths relative to here
python analyzer/modular_cli.py \
    ../ioc_detection/query_responses/exp6_resp_minimal_feb13 \
    --provider deepseek \
    --model deepseek-chat \
    --api-key-file config/deepseek_key.txt \
    --cache cache/ex2_security_embeddings_feb13.pkl \
    --context-file config/ex1_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/7_chunks/ex2_qv3_deepseek_analysis_feb15.md \
    --debug

echo "✅ Analysis complete!"