from InitializerModule.parser import Parser
from AnalysisModule.AnalysisManager import AnalysisManager
import os

def main():
    args = Parser.parseInput()

    if(not (args.ignore_endings is None)):
        file = open(args.ignore_endings, 'r')
        data = file.read()
        ignore_endings = data.split('\n')
        file.close()
    else:
        ignore_endings = []

    if(not (args.ignore_folders is None)):
        file = open(args.ignore_folders, 'r')
        data = file.read()
        ignore_folders = data.split('\n')
        file.close()
    else:
        ignore_folders = []

    usageAnalyzer = AnalysisManager(args.data_dir, args.results_dir, ignore_endings, ignore_folders, args.refresh, args.keep_data)

    usageAnalyzer()

if __name__ == '__main__':
    main()