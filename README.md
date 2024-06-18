# OpenMP usage analysis

## Installation
1. refer to `requirements.txt` to setup the necessary python environment (`pip install -r requirements.txt`)
3. To be able to use the search phase of the program, a GITHUB_KEY has to be present. This has to be a usable GitHub SSH private key, which can be set by using:
```sh
export GITHUB_KEY=<private_key>
```

## Usage
Set the `PYTHONPATH` environment variable to the top level directory of this repo. Scripts offer `--help` option for detailed usage explanation.
* `GitHubSearchModle` is used to query the GitHub API to discover relevant repos, refer to `search_repos.py`
* `AnalyzeModule` is used to perform the analysis of the binaries, refer to `analyze.py`
  * The analysis expects the list of repositories to analyze alongside the scripts to build them. The build scripts can be found in our Data Repository: https://github.com/tudasc/openmp-analysis-data
* The `explore_result.ipnb` jupyther notebook was used to create all the plots in our publication. Note that jupyther is not included in the `requirements.txt` 
