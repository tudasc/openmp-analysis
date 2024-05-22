from InitializerModule.parser import Parser
from AnalysisModule.AnalysisManager import AnalysisManager
import pandas as pd
import os


## invocatipon example: python AnalyzeModule/analyze.py --data_dir /work/scratch/tj75qeje/openmp-usage-analysis-binaries/REPOS/ --results_dir /work/scratch/tj75qeje/openmp-usage-analysis-binaries/RESULTS/ --build_script_dir /work/scratch/tj75qeje/openmp-usage-analysis-binaries/scripts --repo_list /work/scratch/tj75qeje/openmp-usage-analysis-binaries/tj_result.csv

def main():
    args = Parser.parseInput()

    if (not (args.ignore_endings is None)):
        file = open(args.ignore_endings, 'r')
        data = file.read()
        ignore_endings = data.split('\n')
        file.close()
    else:
        ignore_endings = []

    if (not (args.ignore_folders is None)):
        file = open(args.ignore_folders, 'r')
        data = file.read()
        ignore_folders = data.split('\n')
        file.close()
    else:
        ignore_folders = []

    df_repos = pd.read_csv(args.repo_list, index_col=0)
    # filter for those that have a script
    df_repos = df_repos[~df_repos['build_script'].isna()]
    # fully qualify the script path
    df_repos['build_script'] = df_repos['build_script'].apply(lambda x: args.build_script_dir + '/' + str(x))

    # TODO DEBUG ONLY
    df_repos = df_repos.iloc[0:2]

    usageAnalyzer = AnalysisManager(df_repos, args.data_dir, args.results_dir, ignore_endings, ignore_folders,
                                    args.refresh, args.tripcount_guess, args.keep, args.print_cfg)

    usageAnalyzer()


if __name__ == '__main__':
    main()
