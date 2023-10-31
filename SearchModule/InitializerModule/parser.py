import argparse

# This class parses user input. If you wish to extend this, just add a new argument and return it inside of the dict at the end.
# The dict currently contains the path to both files, the name for the DB collection and the API.
class Parser:

    @staticmethod
    def parseInput():
        parser = argparse.ArgumentParser()
        parser.add_argument("--refresh", action='store_true',
                                  help='Re evaluate all repositories and re-fresh their analysis results')
        parser.add_argument("--data_dir", help="location where the repositories should lie", required = True)
        parser.add_argument('--searchqueries',  action='store',
                                  help='Path to the file containing the search query information', required = True)
        parser.add_argument('--codequeries',  action='store',
                                  help='Path to the file containing the code query information', required = True)
        parser.add_argument('--api', nargs='?', choices=['rest', 'graphql'], help='Specify search API (REST or GraphQL)', required = True)
        parser.add_argument('--found_file', action='store', help='Path where the file with the found repos should be lying', required=True)
        parser.add_argument('--evaluated_file', action='store', help='Path where the file with the evaluated repos should be lying', required=True)

        return parser.parse_args()
