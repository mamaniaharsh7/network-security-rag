#!/bin/bash
# Example: Analyze security incidents using OpenAI API

echo "🚀 Running security analysis with OpenAI..."

# Get script directory and navigate to llm_analyzer
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/../../.." || exit 1

# Now we're in llm_analyzer/, use paths relative to here
python analyzer/modular_cli.py ../ioc_detection/query_responses/exp2_feb18 \
    --provider openai \
    --model gpt-5.2 \
    --top-k 7 \
    --api-key-file config/keys/openai_key.txt \
    --cache cache/exp2_embeddings_feb18.pkl \
    --context-file config/ex1_network_context.txt \
    --questions-file config/questions_v5.txt \
    --output reports/exp3_qp/7_chunks/final_Wdomain/openai_5_2.md \
    --debug

echo "✅ Analysis complete! Check reports/openai_5_2_analysis**.md"


