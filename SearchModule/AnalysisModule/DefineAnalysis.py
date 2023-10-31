import pandas as pd

from AnalysisModule.helper import get_preliminary_grep


class DefineAnalysis:

    def __init__(self):
        pass

    def __call__(self, repo):
        repoPath = repo.repoPath

        results = pd.DataFrame(
            columns=['src_location', 'src_location_line_number', 'call', 'defined_token', 'define_value'])

        grep_res = get_preliminary_grep(repoPath, "#define ")

        # set comprehension: remove duplicate filenames
        files = {r[0] for r in grep_res}
        for f in files:
            try:
                normalized = repo.get_normalized_file_content(f)
                for i, l in enumerate(normalized.splitlines()):
                    if l.startswith("#define"):
                        splitted = l.split(' ')
                        if len(splitted) == 3:
                            row = [f, i, "#define", splitted[1], splitted[2]]
                            results.loc[len(results)] = row
            except Exception as e:
                pass

        return results
