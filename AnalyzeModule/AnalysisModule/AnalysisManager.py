import os
import pandas as pd
import tqdm
import multiprocessing as mp
from AnalysisModule.AsmConverter import AsmConverter
from AnalysisModule.AsmAnalyzer import AsmAnalyzer

def convert_to_asm_single_arg(args):
    try:
        convert_to_asm(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
    except Exception:
        print('Transformation of ' + file + ' threw an Exception!')

def analyze_asm_repo_single_arg(args):
    try:
        analyze_asm_repo(args[0], args[2], args[7], args[5], args[6])
    except Exception:
        print('Analyzation of ' + file + ' threw an Exception!')

def run_analysis_on_repo(file, datadir, asmdir, ignore_endings, ignore_folders, refresh_repos, keep_data, resultdir):
    try:
        convert_to_asm(file, datadir, asmdir, ignore_endings, ignore_folders, refresh_repos, keep_data)
        analyze_asm_repo(file, asmdir, resultdir, refresh_repos, keep_data)
    except Exception:
        print(file + " threw an Exception!")

def convert_to_asm(file, datadir, asmdir, ignore_endings, ignore_folders, refresh_repos, keep_data):
    if(os.path.isdir(datadir + '/' + file)):
        if(refresh_repos or not os.path.isdir(asmdir + '/' + file)):
            source = datadir + '/' + file + '/'
            destination = asmdir + '/' + file + '/'
            if(not os.path.isdir(destination)):
                os.mkdir(destination)
            converter = AsmConverter()
            converter(source, destination, ignore_endings, ignore_folders, keep_data)

def analyze_asm_repo(file, asmdir, resultdir, refresh_repos, keep_data):
    outfile = resultdir + '/' + file + '.results'
    if(refresh_repos or not os.path.exists(outfile)):
        source = asmdir + '/' + file + '/'

        analyzer = AsmAnalyzer()
        analyzer(source, outfile, keep_data)
    else:
        pass
        # no analysis

class AnalysisManager:
    __slots__ = ('_datadir', '_asmdir', '_resultdir', '_ignore_endings', '_ignore_folders', '_refresh_repos', '_keep_data')

    def __init__(self, datadir, asmdir, resultdir, ignore_endings, ignore_folders, refresh_repos=False, keep_data=False):
        assert os.path.isdir(datadir) and "The path where the repositories are lying must exist"
        if(not os.path.isdir(asmdir)):
            os.mkdir(asmdir)
        if(not os.path.isdir(resultdir)):
            os.mkdir(resultdir)    
        self._datadir = datadir
        self._asmdir = asmdir
        self._resultdir = resultdir
        self._ignore_endings = ignore_endings
        self._ignore_folders = ignore_folders
        self._refresh_repos = refresh_repos
        self._keep_data = keep_data

    # perform the analyses
    def __call__(self):
        with mp.Pool() as pool:
            param_list = [(file, self._datadir, self._asmdir, self._ignore_endings, self._ignore_folders, self._refresh_repos, self._keep_data, self._resultdir) for
                          file in
                          os.listdir(self._datadir)]
            list(tqdm.tqdm(pool.imap_unordered(convert_to_asm_single_arg, param_list), total=len(param_list)))
            print('Transformation finished.')
            list(tqdm.tqdm(pool.imap_unordered(analyze_asm_repo_single_arg, param_list), total=len(param_list)))
            print('Analysation finished.')

        return 0