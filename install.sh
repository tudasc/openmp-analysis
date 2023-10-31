#!/bin/bash

sudo apt-get update && sudo apt-get upgrade
sudo apt-get install python3
sudo apt-get install python3-venv

python3 -m venv ./venv/openmp-usage-analysis
source ./venv/openmp-usage-analysis/bin/activate
pip install -r requirements.txt

chmod +x ./openmp_usage_analysis_search.sh
chmod +x ./openmp_usage_analysis_analyze.sh
chmod +x ./openmp_usage_analysis_evaluate.sh
