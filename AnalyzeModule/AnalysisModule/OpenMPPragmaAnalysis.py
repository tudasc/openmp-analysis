import re
import subprocess

import pandas as pd

FORMAT_TIMEOUT = 360


# this code is from https://github.com/tudasc/mpi-arg-usage
def is_c_file(file):
    if file.endswith(".c") or file.endswith(".C") or file.endswith(".h") or file.endswith(".H") or file.endswith(
            ".hh") or file.endswith(".I"):
        return True
    else:
        return False


# currently we do not distinguish between c and cpp though
def is_cpp_file(file):
    if file.endswith(".cpp") or file.endswith(".cu") or file.endswith(".cc") or file.endswith(".cxx") or file.endswith(
            ".hpp"):
        return True
    else:
        return False


def is_fortran_file(file):
    if file.endswith(".f") or file.endswith(".F") or file.endswith(".f90") or file.endswith(".F90") or file.endswith(
            ".fpp"):
        return True
    else:
        return False


def is_filetype_supported(file):
    return is_fortran_file(file) or is_c_file(file) or is_cpp_file(file)


# returns list of tirples ech tirple has filename, line number, matching string
# greps a repository for a given string to know which files needs to be analyzed
def get_preliminary_grep(dir, statement):
    try:
        grep_res = subprocess.check_output(f'grep -RnwIi ".*{statement}.*" {dir}', shell=True).decode('utf-8')
        lines = grep_res.splitlines()
        return [l.split(":", maxsplit=3) for l in lines]
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            # print("Error in grep:")
            # print(e.output)
            # this error can occur if some files where not found
            # in this case: stick with the results we got so far
            # this may be the case if some links are contained in the repository
            return [l.split(":", maxsplit=3) for l in e.output.decode('utf-8').splitlines()]
        # else: grep was just empty
        return []


def get_normalized_file_content(self, file):
    if os.path.isfile(file):
        # there may be links, we do not follow those
        if file in self._normalized_files_cache:
            return self._normalized_files_cache[file]
        else:
            if is_c_file(file) or is_cpp_file(file):
                try:
                    result = subprocess.check_output(
                        f'clang-format -style=\'{{ColumnLimit: 100000,'
                        f'AllowAllArgumentsOnNextLine: false, '
                        f'AllowShortFunctionsOnASingleLine: false, '
                        f'AllowShortLoopsOnASingleLine: false, '
                        f'AllowShortCaseLabelsOnASingleLine: false, '
                        f'BreakBeforeBraces: Allman, '
                        f'BinPackArguments: true, '
                        f'PenaltyBreakBeforeFirstCallParameter: 100000 }}\' {file} | gcc -fpreprocessed -dD -E -',
                        stderr=subprocess.DEVNULL, shell=True, text=True, timeout=FORMAT_TIMEOUT)
                    # clang-format should also normalize any pragma lines (#pragma omp)
                    self._normalized_files_cache[file] = result
                    return result
                except subprocess.CalledProcessError as e:
                    print("FormattingError in pre-processing file:")
                    print(file)
                    # print(e.output)
                    return ""
                except UnicodeDecodeError as e:
                    print("UnicodeDecodeError in pre-processing file:")
                    print(file)
                    return ""
            elif is_fortran_file(file):
                # fprettyfy has a bug, when we want to read a file to stdin, so we need to cat and pipe
                try:
                    formatted = subprocess.check_output(
                        f'cat {file} | fprettify --strip-comments --disable-indent --disable-whitespace --line-length 1000000 ',
                        stderr=subprocess.DEVNULL, shell=True, text=True, timeout=FORMAT_TIMEOUT)
                    # remove all comments
                    # l[l.find('!')+1:] will only include everything before the first ! (or all if no !)
                    lines = [l.strip() for l in formatted.splitlines()]
                    no_comments = [l[l.find('!') + 1:] if not l.upper().startswith('!$OMP') else l
                                   for l in lines if
                                   not (
                                           l.startswith('c ') or l.startswith('C ')
                                           or l.startswith('*') or l.startswith('d') or l.startswith('D')
                                           or (l.startswith('!') and not l.upper().startswith('!$OMP'))
                                   )]

                    result = "\n".join(no_comments)

                    # normalize the pragma omp lines into one line
                    # free form
                    result = re.sub("&\n(\!\$(OMP|omp))", "", result)
                    # fixed form
                    result = re.sub("\n(\!\$(OMP|omp)&)", "", result)

                    # format everything into one line if a statement is split up
                    # & introduces a new line that may start immediately or after the next &
                    result = re.sub("&\n([ \t]*&)?", "", result)

                    # Fortran is case-insensitive: normalize to uppercase as the usual form
                    result = result.upper()

                    self._normalized_files_cache[file] = result
                    return result
                except subprocess.CalledProcessError as e:
                    print("FormattingError in pre-processing file:")
                    print(file)
                    # print(e.output)
                    return ""
                except UnicodeDecodeError as e:
                    print("UnicodeDecodeError in pre-processing file:")
                    print(file)
                    return ""
            else:
                # print(f" file format not supported: {file} Skip this file")
                pass
    return ""


class OpenmpAnalysis:

    def __init__(self):
        pass

    def __call__(self, path):

        results = pd.DataFrame(
            columns=['src_location', 'src_location_line_number', 'call', 'openmp_pragma_used'])

        grep_res = get_preliminary_grep(path, "omp")

        # set comprehension: remove duplicate filenames
        files = {r[0] for r in grep_res}
        for f in files:
            try:
                normalized = get_normalized_file_content(f)
                for i, l in enumerate(normalized.splitlines()):
                    if l.startswith("#pragma omp"):
                        row = [f, i, "openmp", l[11:]]
                        results.loc[len(results)] = row
                    if l.startswith("!$OMP") or l.startswith("!$omp"):
                        row = [f, i, "openmp", l[5:]]
                        results.loc[len(results)] = row

            except Exception as e:
                pass

        return results
