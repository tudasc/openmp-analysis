import argparse

# This class parses user input. If you wish to extend this, just add a new argument and return it inside of the dict at the end.
# The dict currently contains the path to both files, the name for the DB collection and the API.
class Parser:

    @staticmethod
    def parseInput():
        parser = argparse.ArgumentParser()
        parser.add_argument("--refresh", action='store_true',
                                  help='Re evaluate all repositories and re-fresh their statistics')
        parser.add_argument("--data_dir", help="location where the repositories are stored", required = True)
        parser.add_argument('--results_dir', help='location where the analysation results are stored', required = True)
        parser.add_argument('--statistics_dir', help='location where the statistics should be stored', required = True)
        parser.add_argument('--evaluated_file', action='store', help='Path where the file with the evaluated repos should be lying')
        parser.add_argument('--pragmas_file', default='./EvaluationModule/openmp_pragmas.txt', action='store', help='Path to the file, which contains the types of openmp pragmas.')
        parser.add_argument('--overhead_high', help='The overhead for thread creation with many threads.', type=int, required = True)
        parser.add_argument('--overhead_low', help='The overhead for thread creation with few threads.', type=int, required=True)

        return parser.parse_args()