import argparse

import pandas as pd
import os


## invocatipon example: python AnalyzeModule/merge_results.py --results_dir /work/scratch/tj75qeje/openmp-usage-analysis-binaries/RESULTS/ --skip_o

def main():
    parser = argparse.ArgumentParser(
        description="Collect data from all repositories into one large dataframe for later analysis")
    parser.add_argument('--output', default='result.csv',
                        help='output file')
    parser.add_argument('--results_dir', default='RESULTS',
                        help='where the repos are listed with teh build instructions')
    parser.add_argument('--skip_o', action='store_true',default=False,
                        help='if results from .o files should be excluded')

    ARGS= parser.parse_args()

    base_dir = ARGS.results_dir
    df_full = pd.DataFrame()
    for root, dirs, files in os.walk(base_dir):
        for name in files:
            if name.endswith(".csv"):
                if not name.endswith(".o.csv") or not ARGS.skip_o:
                    this_repo = os.path.basename(os.path.normpath(root))
                    this_file = os.path.join(root, name)
                    this_df = pd.read_csv(this_file, index_col=0)
                    this_df["Code"] = this_repo
                    # remove the ".csv" in original file name to get binary name
                    this_df["File"] = os.path.basename(this_file)[:-4]
                    df_full = pd.concat([df_full, this_df])

    df_full.to_csv(ARGS.output)


if __name__ == '__main__':
    main()
