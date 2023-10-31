from GithubRepoSearchModule.api import API
from GithubRepoSearchModule.searchQueryFactory import SearchQueryFactory
from GithubRepoSearchModule.searchQueryConsumerFactory import SearchQueryConsumerFactory
from AnalysisModule.AnalysisManager import AnalysisManager
from AnalysisModule.OpenMPAnalysis import OpenMPAnalysis
from InitializerModule.parser import Parser

import copy
import os
import pandas as pd

def main():
    args = Parser.parseInput()

    if args.api == 'rest':
        api = API.GithubRest
    elif args.api == 'graphql':
        api = API.GithubGraphQL

    if args.refresh or not os.path.isfile(args.found_file):
        print('Searching for repositories...')
        s = SearchQueryFactory.getSearchQuery(api, args.searchqueries)
        c = SearchQueryConsumerFactory.getConsumer(api, s)
        c.startSearch()
    
        c.reportRepos().to_csv(args.found_file)
        print('Found repositories written to: ' + args.found_file)

    dataDir = args.data_dir
    if not os.path.isdir(dataDir):
        os.mkdir(dataDir)

    repoAnalyzer = AnalysisManager(dataDir, args.refresh)

    repoAnalyzer.register_analysis(OpenMPAnalysis())
    
    df = pd.read_csv(args.found_file, header=0, index_col=0)

    repoAnalyzer(df).to_csv(args.evaluated_file)
    print('Evaluated repositories written to: ' + args.evaluated_file)

if __name__ == "__main__":
    main()