import pandas as pd
import tqdm
import traceback
import shutil

import multiprocessing as mp

import os

from AnalysisModule.Repository import Repository
from AnalysisModule.OpenMPAnalysis import OpenMPAnalysis


# This dummy class shows the Properties an analysis object must have to serve as a reference
class DummyAnalysis:

    # def __init__(self):
    # one may need a constructor

    # the call method will be invoked by the analysis manager to run the ananlysis on the given repo
    # returns a pandas dataframe with the resulting data for this repo
    # the index of the dataframe is not important and will be ignored anyway
    def __call__(self, repo):
        return pd.DataFrame(columns=["Dummy_Metric1", "Dummy_Metric2"], data=[[0, 0], [1, 1]])


# helper for running an analysis
def run_analysis_on_repo_single_arg(args):
    try:
        return run_analysis_on_repo(args[0], args[1], args[2], args[3], args[4])
    except Exception:
        print("Analyzation of repo with name: " + args[1]['Code'] + ", aborted, because it threw an Exception!")
        return None

def run_analysis_on_repo(index, row, repopath, refresh_repos, analyses):
    result_df = pd.DataFrame()
    repo = Repository(repoName=row['Code'], repoUrl=row['URL'], repoType=row['Type'],
                      repoPath=repopath + '/' + row['Code'])
    this_repo_result_file = repopath + '/' + row['Code'] + '/' + 'results.csv'
    repo.cloneRepo(refresh_repos)
    if (not refresh_repos) and os.path.isfile(this_repo_result_file):
        result_df = pd.read_csv(this_repo_result_file, header=0)
        if(len(result_df) == 0):
            return None
        else:
            return row
    else:
        if repo.is_supported:
            for analysis in analyses:
                analysis_result = analysis(repo)
                analysis_result['Code'] = row['Code']
                result_df = pd.concat((result_df, analysis_result), axis=0, ignore_index=True)
            # finished analysis
            if(len(result_df) == 0):
                shutil.rmtree(repo.repoPath)
                os.mkdir(repo.repoPath)
                result_df.to_csv(this_repo_result_file)
                return None
            else:
                result_df.to_csv(this_repo_result_file)
                return row

        else:
            pass
            # no analysis


# manages all analysis done for a repo
class AnalysisManager:
    __slots__ = ('_analyses', '_repopath', '_refresh_repos')

    def __init__(self, repopath, refresh_repos=False, analyses=[]):
        self._analyses = analyses
        assert os.path.isdir(repopath) and "The path where the repositories should be downloaded to must exist"
        self._repopath = repopath
        self._refresh_repos = refresh_repos

    def register_analysis(self, analysis):
        self._analyses.append(analysis)

    # perform the analyses
    def __call__(self, input_df):
        with mp.Pool() as pool:
            param_list = [(index, row, self._repopath, self._refresh_repos, self._analyses) for
                          index, row in
                          input_df.iterrows()]
            evaluated_repos = list(tqdm.tqdm(pool.imap_unordered(run_analysis_on_repo_single_arg, param_list),
                                        total=len(param_list)))

        output_df = pd.DataFrame.from_records(list(filter(lambda item: item is not None, evaluated_repos)))

        return output_df
