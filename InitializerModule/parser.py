import argparse

# This class parses user input. If you wish to extend this, just add a new argument and return it inside of the dict at the end.
# The dict currently contains the path to both files, the name for the DB collection and the API.
class Parser:

    @staticmethod
    def parseInput():
        parser = argparse.ArgumentParser()
        parser.add_argument('mode', choices=['search', 'analyze', 'evaluate'],
                                  help='Mode to use: either analyze: run the analysis on the given repos; search: search for repos on github; evaluate: create the statistics out of the given result files')
        parser.add_argument('--refresh', action='store_true',
                                  help='Re evaluate all repositories and re-fresh their analysis results')
        parser.add_argument('--data_dir', default='./data/raw', help='Location where the repositories should be lying')
        
        groupSparser = parser.add_argument_group('Search', 'Arguments when searching for github repos')
        groupSparser.add_argument('--searchqueries', default='./SearchModule/queries/default_search.queries', action='store',
                                  help='Path to the file containing the search query information')
        groupSparser.add_argument('--codequeries', default='./SearchModule/queries/default_code.queries', action='store',
                                  help='Path to the file containing the code query information')
        groupSparser.add_argument('--api', nargs='?', default='rest', choices=['rest', 'graphql'], help='Specify search API (REST or GraphQL)')
        groupSparser.add_argument('--found_file', default='./data/found_repos.csv', action='store', help='Path where the file with the found repos should be lying')
        groupSparser.add_argument('--evaluated_file', default='./data/evaluated_repos.csv', action='store', help='Path where the file with the evaluated repos should be lying')

        groupAparser = parser.add_argument_group('Analysis', 'Arguments used in analysis mode')
        groupAparser.add_argument('--keep_data', action='store_true', help='Keep all data even, when finished working on')
        groupAparser.add_argument('--built_dir', default = './data/built', help='Location where the built repositories are lying')
        groupAparser.add_argument('--asm_dir', default = './data/asm', help='Location where the asm files should be lying')
        groupAparser.add_argument('--results_dir', default='./data/results', help='Location where the results should be lying')
        groupAparser.add_argument('--ignore_endings', default='./AnalyzeModule/AnalysisModule/ignore_endings.txt', action='store', help='Path to the file containing the file endings to be ignored.')
        groupAparser.add_argument('--ignore_folders', default='./AnalyzeModule/AnalysisModule/ignore_folders.txt', action='store', help='Path to the file containing the folder names to be ignored.')

        groupEparser = parser.add_argument_group('Evaluation', 'Arguments used in evaluate mode')
        groupEparser.add_argument('--result_dir', default='./data/results', help='Location where the results should be lying')
        groupEparser.add_argument('--statistics_dir', default='./data/statistics', help='Location where the generated statistics should be lying')
        groupEparser.add_argument('--repos_file', default='./data/evaluated_repos.csv', action='store', help='The file with the information about the found repos, that utilize OpenMP')
        groupEparser.add_argument('--pragmas_file', default='./EvaluateModule/EvaluationModule/openmp_pragmas.txt', action='store', help='Path to the file, which contains the types of openmp pragmas.')
        groupEparser.add_argument('--overhead_high', default=2813, help='The overhead for thread creation with many threads.', type=int)
        groupEparser.add_argument('--overhead_low', default=375, help='The overhead for thread creation with few threads.', type=int)

        return parser.parse_args()
