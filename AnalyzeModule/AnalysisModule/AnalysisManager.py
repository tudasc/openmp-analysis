import os
import tqdm
from tqdm.auto import tqdm

tqdm.pandas()
import multiprocessing as mp
import pandas as pd
from AnalysisModule.AsmAnalyzer import AsmAnalyzer
import magic
import subprocess
import shutil

from pandarallel import pandarallel

pandarallel.initialize(nb_workers=24, progress_bar=True)

# for debugging
CONTINUE_ON_EXCEPTION = False

PRINT_ANALYZED_FILES = False
USE_PARALLEL_PROCESSING = True


def cloneRepo(repoUrl, path, commit_hash=None):
    try:
        # remove any old repo
        if not os.path.isdir(path):
            # not already present:
            # download
            subprocess.check_output(f'git clone --depth 1 {repoUrl} {path}', stderr=subprocess.STDOUT, shell=True,
                                    encoding='UTF-8')

        # get current hash, remove trailing \n
        current_hash = subprocess.check_output(f'git rev-parse --verify HEAD', cwd=path, stderr=subprocess.STDOUT,
                                               shell=True, encoding='UTF-8').strip()
        if commit_hash is None or current_hash == commit_hash:
            return current_hash
        else:
            # fetch different revision
            # TODO one could check that origin-url is set up correctly
            subprocess.check_output(f'git fetch --depth 1 origin {commit_hash}', cwd=path, stderr=subprocess.STDOUT,
                                    shell=True, encoding='UTF-8')
            subprocess.check_output(f'git checkout {commit_hash}', cwd=path, stderr=subprocess.STDOUT,
                                    shell=True, encoding='UTF-8')
            return commit_hash

    except subprocess.CalledProcessError as e:
        print("ERROR: downloading Repo:")
        print(e.output)


def build_repo(path, build_script):
    assert os.path.isfile(build_script)
    try:
        output = subprocess.check_output("%s %s -O0" % (build_script, path), cwd=path,
                                         stderr=subprocess.STDOUT,
                                         shell=True, encoding='UTF-8')
        print(output)
        if "BUILD SUCCESSFUL" in output:
            return True
        else:
            return False

    except subprocess.CalledProcessError as e:
        print("ERROR: building Repo:")
        print(e.output)
    return False


def analyze_asm_repo_single_arg(args):
    if CONTINUE_ON_EXCEPTION:
        try:
            analyze_asm_repo(args)
        except Exception:
            print('Analysis of ' + args["Code"].replace('/', '--') + ' threw an Exception!')
    else:
        analyze_asm_repo(args)


def analyze_asm_repo(row, print_analyzed_repos=True, print_analyzed_files=False):
    repo_name = row["Code"].replace('/', '--')
    repo_base_path = row["datadir"]
    repo_path = os.path.join(repo_base_path, repo_name)
    if print_analyzed_repos:
        print("Download %s" % repo_name)
    cloneRepo(row["URL"], repo_path, row["usedHash"])
    if print_analyzed_repos:
        print("Build %s" % repo_name)
    build_repo(repo_path, row["build_script"])
    if print_analyzed_repos:
        print("Analyze %s" % repo_name)

    outdir = os.path.join(row["resultdir"], repo_name)
    os.makedirs(outdir, exist_ok=True)

    for root, dirs, files in os.walk(repo_path):
        # https://stackoverflow.com/questions/19859840/excluding-directories-in-os-walk
        # modifying dirs in-place will prune the (subsequent) files and directories visited by os.walk
        dirs[:] = [d for d in dirs if d not in row["ignore_folders"]]
        for name in files:
            this_file = os.path.join(root, name)
            file_type = magic.from_file(this_file, mime=True)
            # only analyze binary or object files
            analyze = file_type.startswith('application/x-executable') or file_type.startswith(
                'application/x-object') or file_type.startswith('application/x-sharedlib')
            # print(this_file)
            # print(file_type)

            for suffix in row["ignore_endings"]:
                if this_file.endswith(suffix):
                    analyze = False

            if analyze:
                if PRINT_ANALYZED_FILES:
                    print("analyze file: %s" % this_file)
                analyzer = AsmAnalyzer()
                outname = name + ".csv"
                analyzer(this_file, os.path.join(outdir, outname), row["tripcount_guess"], row["print_cfg"])
            else:
                if print_analyzed_files:
                    print("skip file %s" % this_file)

    else:
        pass
        # no analysis


class AnalysisManager:
    __slots__ = (
        '_df_repos', '_datadir', '_asmdir', '_resultdir', '_ignore_endings', '_ignore_folders', '_refresh_repos',
        '_tripcount_guess',
        '_print_cfg')

    # TODO: refactor: we dont need an object for this
    def __init__(self, df_repos, datadir, resultdir, ignore_endings, ignore_folders, refresh_repos, tripcount_guess,
                 print_cfg):
        assert os.path.isdir(datadir) and "The path where the repositories are lying must exist"
        if refresh_repos and os.path.isdir(resultdir):
            shutil.rmtree(resultdir, ignore_errors=True)
        os.makedirs(resultdir, exist_ok=True)
        self._df_repos = df_repos

        self._df_repos["datadir"] = datadir
        self._datadir = datadir
        if refresh_repos and os.path.isdir(datadir):
            shutil.rmtree(datadir, ignore_errors=True)
        os.makedirs(datadir, exist_ok=True)

        self._resultdir = resultdir
        self._df_repos["resultdir"] = resultdir
        self._df_repos["ignore_folders"] = [ignore_folders] * len(df_repos)
        self._df_repos["ignore_endings"] = [ignore_endings] * len(df_repos)
        # for usage without angr_utils
        assert print_cfg == False
        self._df_repos["print_cfg"] = False
        self._df_repos["tripcount_guess"] = tripcount_guess

    # perform the analyses
    def __call__(self):
        with mp.Pool() as pool:

            # filter out the repos where we have already collected some data
            existing_files = os.listdir(self._resultdir)
            df_repos = self._df_repos[
                self._df_repos["Code"].apply(lambda x: x.replace('/', '--') not in existing_files)]

            if USE_PARALLEL_PROCESSING:
                # parallel processing
                df_repos.parallel_apply(analyze_asm_repo_single_arg, axis=1)
            else:
                # serial processing
                df_repos.progress_apply(analyze_asm_repo_single_arg, axis=1)

            print('Analysis finished.')

        return 0
