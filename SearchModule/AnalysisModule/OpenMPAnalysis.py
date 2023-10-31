import pandas as pd

from AnalysisModule.Helper import get_preliminary_grep

ENDINGS = ['c', 'cc', 'C', 'cpp', 'cxx', 'c++', 'h', 'hh', 'H', 'hpp', 'hxx', 'h++', 't', 'tt', 'T', 'tpp', 'txx', 't++']

class OpenMPAnalysis:
    # __slots__ = ('_query', '_type_arg_nun')

    def __init__(self):
        pass

    def __call__(self, repo):
        repoPath = repo.repoPath

        results = pd.DataFrame(
            columns=['src_location', 'src_location_line_number', 'call', 'openmp_pragma_used'])

        grep_res = get_preliminary_grep(repoPath, "omp")

        # set comprehension: remove duplicate filenames
        files = {r[0] for r in grep_res}
        for f in files:
            if(f.split('.')[len(f.split('.'))-1] in ENDINGS):
                try:
                    with open(f, 'r') as fileContent:
                        for lineNumber, line in enumerate(fileContent):  
                            splitted = line.split()            
                            if "#pragma omp" in line:
                                row = [f, lineNumber, "openmp", splitted[2:]]
                                results.loc[len(results)] = row
                            if "!$OMP" in line or "!$omp" in line:
                                row = [f, lineNumber, "openmp", splitted[1:]]
                                results.loc[len(results)] = row

                except Exception as e:
                    pass

        return results
        

