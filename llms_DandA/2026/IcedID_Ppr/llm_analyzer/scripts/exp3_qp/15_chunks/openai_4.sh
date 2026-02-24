#!/bin/bash
# Example: Analyze security incidents using OpenAI API

echo "🚀 Running security analysis with OpenAI..."

# Get script directory and navigate to llm_analyzer
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/../../.." || exit 1

# Now we're in llm_analyzer/, use paths relative to here
python analyzer/modular_cli.py ../ioc_detection/query_responses/exp2_feb18 \
    --provider openai \
    --model gpt-4 \
    --top-k 15 \
    --api-key-file config/keys/openai_key.txt \
    --cache cache/exp2_embeddings_feb18.pkl \
    --context-file config/ex1_network_context.txt \
    --questions-file config/questions_v4.txt \
    --output reports/exp3_qp/15_chunks/openai_4.md \
    --debug

echo "✅ Analysis complete! Check reports/openai_4_analysis**.md"


