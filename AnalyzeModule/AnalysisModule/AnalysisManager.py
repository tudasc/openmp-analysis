import os
import pandas as pd
import tqdm
import multiprocessing as mp
from AnalysisModule.AsmAnalyzer import AsmAnalyzer
from binaryornot.check import is_binary


def analyze_asm_repo_single_arg(args):
    try:
        analyze_asm_repo(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
    except Exception:
        print('Analysis of ' + args[0] + ' threw an Exception!')


def analyze_asm_repo(repo_name, repo_base_path, resultdir, ignore_endings, ignore_folders, refresh_repos, keep_data,
                     print_analyzed_files=False):
    outdir = os.path.join(resultdir, repo_name)
    os.makedirs(outdir, exist_ok=True)

    for root, dirs, files in os.walk(os.path.join(repo_base_path, repo_name)):
        #https://stackoverflow.com/questions/19859840/excluding-directories-in-os-walk
        #modifying dirs in-place will prune the (subsequent) files and directories visited by os.walk
        dirs[:] = [d for d in dirs if d not in ignore_folders]
        for name in files:
            this_file = os.path.join(root, name)
            analyze = is_binary(this_file)
            for suffix in ignore_endings:
                if this_file.endswith(suffix):
                    analyze = False

            if analyze:
                if print_analyzed_files:
                    print("analyze file: %s" % this_file)
                analyzer = AsmAnalyzer()
                outname = name + ".csv"
                analyzer(this_file, os.path.join(outdir, outname))
            else:
                if print_analyzed_files:
                    print("skip file %s" % this_file)

    else:
        pass
        # no analysis


class AnalysisManager:
    __slots__ = (
        '_datadir', '_asmdir', '_resultdir', '_ignore_endings', '_ignore_folders', '_refresh_repos', '_keep_data')

    def __init__(self, datadir, resultdir, ignore_endings, ignore_folders, refresh_repos=False, keep_data=True):
        assert os.path.isdir(datadir) and "The path where the repositories are lying must exist"
        if (not os.path.isdir(resultdir)):
            os.mkdir(resultdir)
        self._datadir = datadir
        self._resultdir = resultdir
        self._ignore_endings = ignore_endings
        self._ignore_folders = ignore_folders
        self._refresh_repos = refresh_repos
        self._keep_data = keep_data

    # perform the analyses
    def __call__(self, use_parallel_processing=True):
        with mp.Pool() as pool:
            param_list = [(repo_dir, self._datadir, self._resultdir, self._ignore_endings, self._ignore_folders,
                           self._refresh_repos,
                           self._keep_data) for
                          repo_dir in
                          os.listdir(self._datadir)]

            if use_parallel_processing:
                # parallel processing
                list(tqdm.tqdm(pool.imap_unordered(analyze_asm_repo_single_arg, param_list), total=len(param_list)))
            else:
                # serial processing
                [analyze_asm_repo_single_arg(p) for p in param_list]

            print('Analysis finished.')

        return 0
