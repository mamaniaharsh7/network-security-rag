#!/bin/bash
# Example: Analyze security incidents using DeepSeek API

echo "🚀 Running security analysis with DeepSeek..."

# Get script directory and navigate to llm_analyzer
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# Now we're in llm_analyzer/, use paths relative to here
python analyzer/modular_cli.py ../ioc_detection/query_responses/exp1_resp_minimal_feb17_paper \
    --provider deepseek \
    --model deepseek-chat \
    --api-key-file config/keys/deepseek_key.txt \
    --cache cache/ex1_security_embeddings_feb17_paper.pkl \
    --context-file config/ex1_network_context.txt \
    --questions-file config/questions_v3.txt \
    --output reports/7_chunks/ex1_qv3_deepseek_analysis_feb17_paper.md \
    --debug

echo "✅ Analysis complete! Check reports/deepseek_analysis**.md"