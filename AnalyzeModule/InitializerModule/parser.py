import argparse


# This class parses user input. If you wish to extend this, just add a new argument and return it inside of the dict at the end.
# The dict currently contains the path to both files, the name for the DB collection and the API.
class Parser:

    @staticmethod
    def parseInput():
        parser = argparse.ArgumentParser(
            description="Analyzes all repositories (directories) in --data_dir. collect all results to --results_dir.")
        parser.add_argument("--refresh", action='store_true', default=False,
                            help='Re evaluate all repositories and re-fresh their analysis results')
        parser.add_argument("--print_cfg", action='store_true', default=False,
                            help='prints a CFG for each binary analyzed')
        parser.add_argument("--data_dir", help="Location where the repositories are lying", required=True)
        parser.add_argument("--results_dir", help="Location where the results should be stored", required=True)
        parser.add_argument("--ignore_endings", default=None, action='store',
                            help='Path to the file containing the file endings to be ignored.')
        parser.add_argument("--ignore_folders", default=None, action="store",
                            help="Path to the file containing the folder names to be ignored.")
        parser.add_argument("--tripcount_guess", default=3, type=int, action='store',
                            help='Guess of tripcount for loops (use --refresh to re-analyze all repos when chainging the guess)')
        parser.add_argument('--build_script_dir', default='./data/raw',
                            help='Location where the build scripts are located')
        parser.add_argument('--repo_list', default='repos.csv',
                            help='where the repos are listed with teh build instructions')

        return parser.parse_args()
