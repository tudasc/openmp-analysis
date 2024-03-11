import os
import tqdm
import multiprocessing as mp
from AnalysisModule.AsmAnalyzer import AsmAnalyzer
import magic

# for debugging
CONTINUE_ON_EXCEPTION = False

PRINT_ANALYZED_FILES = True


def analyze_asm_repo_single_arg(args):
    if CONTINUE_ON_EXCEPTION:
        try:
            analyze_asm_repo(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
        except Exception:
            print('Analysis of ' + args[0] + ' threw an Exception!')
    else:
        analyze_asm_repo(args[0], args[1], args[2], args[3], args[4], args[5], args[6])


def analyze_asm_repo(repo_name, repo_base_path, resultdir, ignore_endings, ignore_folders, print_cfg, tripcount_guess,
                     print_analyzed_files=False):
    outdir = os.path.join(resultdir, repo_name)
    os.makedirs(outdir, exist_ok=True)

    for root, dirs, files in os.walk(os.path.join(repo_base_path, repo_name)):
        # https://stackoverflow.com/questions/19859840/excluding-directories-in-os-walk
        # modifying dirs in-place will prune the (subsequent) files and directories visited by os.walk
        dirs[:] = [d for d in dirs if d not in ignore_folders]
        for name in files:
            this_file = os.path.join(root, name)
            file_type = magic.from_file(this_file, mime=True)
            # only analyze binary or object files
            analyze = file_type.startswith('application/x-executable') or file_type.startswith('application/x-object') or file_type.startswith('application/x-sharedlib')
            print(this_file)
            print(file_type)

            for suffix in ignore_endings:
                if this_file.endswith(suffix):
                    analyze = False

            if analyze:
                if PRINT_ANALYZED_FILES:
                    print("analyze file: %s" % this_file)
                analyzer = AsmAnalyzer()
                outname = name + ".csv"
                analyzer(this_file, os.path.join(outdir, outname), tripcount_guess, print_cfg)
            else:
                if print_analyzed_files:
                    print("skip file %s" % this_file)

    else:
        pass
        # no analysis


class AnalysisManager:
    __slots__ = (
        '_datadir', '_asmdir', '_resultdir', '_ignore_endings', '_ignore_folders', '_refresh_repos', '_tripcount_guess',
        '_print_cfg')

    # TODO: refactor: we dont need an object for this
    def __init__(self, datadir, resultdir, ignore_endings, ignore_folders, refresh_repos, tripcount_guess, print_cfg):
        assert os.path.isdir(datadir) and "The path where the repositories are lying must exist"
        os.makedirs(resultdir, exist_ok=True)
        self._datadir = datadir
        self._resultdir = resultdir
        self._ignore_endings = ignore_endings
        self._ignore_folders = ignore_folders
        self._refresh_repos = refresh_repos
        self._print_cfg = print_cfg
        self._tripcount_guess = tripcount_guess

    # perform the analyses
    def __call__(self, use_parallel_processing=True):
        with mp.Pool() as pool:
            param_list = [
                (repo_dir, self._datadir, self._resultdir, self._ignore_endings, self._ignore_folders,
                 self._tripcount_guess, self._print_cfg)
                for
                repo_dir in
                os.listdir(self._datadir)]

            # filter out the repos where we have already collected some data
            if not self._refresh_repos:
                param_list = [p for p in param_list if not p[0] in os.listdir(self._resultdir)]

            if use_parallel_processing:
                # parallel processing
                list(tqdm.tqdm(pool.imap_unordered(analyze_asm_repo_single_arg, param_list), total=len(param_list)))
            else:
                # serial processing
                [analyze_asm_repo_single_arg(p) for p in param_list]

            print('Analysis finished.')

        return 0
