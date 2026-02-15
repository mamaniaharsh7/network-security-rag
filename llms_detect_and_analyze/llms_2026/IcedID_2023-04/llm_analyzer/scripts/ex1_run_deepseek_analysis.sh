# I ran the first experiment directly from the command line. (Script available from 2nd Experimnet onwards)

# Here are the commands I used:

# --- In VS Code terminal:
source venv\Scripts\activate

# ---------- Setup ----------
cd llms_detect_and_analyze\llm_analyzer

pip install -r requirements.txt

mkdir config\keys # i did this in the root folder though
echo YOUR_API_KEY_HERE > config\keys\deepseek_key.txt


# ---------- STEP 1: Note the Time Range ---------- 
# Your PCAP spans: 2023-04-19 through 2023-04-19

# ---------- STEP 2: Run IOC Detection Queries ----------

# Before Step 2, you need SSH tunnel running:
# Open a separate terminal and keep this running:
ssh -L 9200:localhost:9200 onion@yourserver.myuni.com -N

# Now, On your local machine (NOT in SSH), in Git Bash terminal:

# Navigate to IOC detection folder
cd llms_detect_and_analyze/llms_2026/ioc_detection

# Activate venv
source ../../../venv/Scripts/activate

# Create output folder for IcedID results
mkdir -p icedid_resp_2023april_oldqueries

pip install python-dotenv

# Update .env with your actual Kibana credentials:
# ELASTICSEARCH_HOST=https://localhost:9200
# ELASTICSEARCH_USERNAME=<your-kibana-email>
# ELASTICSEARCH_PASSWORD=<your-kibana-password>

python -u query_executor_with_time_range.py queries_minimal query_responses/icedid_resp_2023april_oldqueries/ --start-date=2023-04-19 --end-date=2023-04-19

# ---------- STEP 3: Build Embeddings Cache for IcedID Data ----------
# Navigate to LLM analyzer
cd ../llm_analyzer

# Create symlink to new results
ln -s ../ioc_detection/icedid_resp_2023april_oldqueries data_icedid

# Build cache
python analyzer/modular_cli.py ./data_icedid --build-cache-only --cache cache/icedid_2023april_oldqueries_embeddings.pkl

# ---------- STEP 4: Run LLM Analysis ---------- 
# Create reports subfolder
mkdir -p reports/icedid_2023april_oldqueries_oldquestions

# Run analysis
python analyzer/modular_cli.py ./data_icedid --provider deepseek --api-key-file ../config/keys/deepseek_key.txt --cache cache/icedid_2023april_oldqueries_embeddings.pkl --output reports/icedid_2023april_oldqueries_oldquestions/

# ---------- STEP 5: Review Results ----------
# View the generated report
ls reports/icedid_2023april_oldqueries_oldquestions/

# Open in VS Code
code reports/icedid_2023april_oldqueries_oldquestions/incident_analysis_*.md

# ---------- STEP 6: Push to GitHub ---------- 
# Go to root directory
cd ../../..

# Check what's changed
git status

# Add all new files
git add .

# Commit
git commit -m "Complete IcedID pipeline: IOC detection + LLM analysis on 2023-04-19 dataset"

# Push
git push origin harsh-dev