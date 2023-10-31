# OpenMP usage analysis

## Installation
1. Make the install.sh script executable with:
```sh
chmod +x install.sh
```
2. Run install.sh to install the requirements. Warning sudo rights required.
3. To be able to use the search phase of the program, a GITHUB_KEY has to be present. This has to be a usable GitHub SSH private key, which can be set by using:
```sh
export GITHUB_KEY=<private_key>
```

## Usage
If it is not active, activate the environment, by running:
```sh
source ./venv/openmp_usage_analysis/bin/activate
```
The program has three possible executable phases: **search**, **analyze** and **evaluate**. Each of them can be run with:
```sh
python3 openmp_usage_analysis.py <phase_type>
```
The possible execution variables and their explanations can be shown with:
```sh
python3 openmp_usage_analysis.py --help