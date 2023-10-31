import os
import subprocess
from datetime import datetime
import re

from AnalysisModule.Helper import *

FORMAT_TIMEOUT = 360


# This class represents a singular repository.
# currently repos are privided via git or a tar.gz file
class Repository:
    __slots__ = (
        '_repoName', '_repoType', '_repoUrl', '_repoPath', '_repoType', '_is_supported', '_normalized_files_cache')

    def __init__(self, repoName, repoType, repoPath, repoUrl=None):
        self._repoName = repoName
        self._repoPath = repoPath
        self._repoUrl = repoUrl
        self._repoType = repoType
        self._is_supported = False
        self._normalized_files_cache = {}

    def cloneRepo(self, re_download=False):

        try:
            # remove any old repo
            if os.path.isdir(self._repoPath):
                if re_download:
                    subprocess.check_output(f'rm -rf {self._repoPath}', stderr=subprocess.STDOUT, shell=True)
                else:
                    # already present
                    self._is_supported = True
                    return

            # download a new repo
            if self._repoType == 'git' and self._repoUrl:
                subprocess.check_output(f'git clone --depth 1 {self._repoUrl} {self._repoPath}',
                                        stderr=subprocess.STDOUT, shell=True)
                self._is_supported = True
            elif self._repoType == 'tar.gz' and self._repoUrl:
                subprocess.check_output(f'wget -O {self._repoPath}.tar.gz {self._repoUrl}', stderr=subprocess.STDOUT,
                                        shell=True)
                os.mkdir(self._repoPath)
                subprocess.check_output(f'tar -xzf {self._repoPath}.tar.gz -C {self._repoPath}',
                                        stderr=subprocess.STDOUT,
                                        shell=True)
                # remove temporary
                os.remove("%s.tar.gz" % self._repoPath)
                self._is_supported = True
            elif self._repoType == 'local' and self._repoUrl:
                os.mkdir(self._repoPath)
                if(self._repoUrl[-1] != '/'):
                    self._repoUrl = self._repoUrl + '/'
                subprocess.check_output(f'cp -R {self._repoUrl}* {self._repoPath}', stderr=subprocess.STDOUT,
                                            shell=True)
                self._is_supported = True
            else:
                print("ERROR: Repo type %s is currently not supported" % self._repoType)
                # make empty dir instead
                os.mkdir(self._repoPath)
                self._is_supported = False
        except subprocess.CalledProcessError as e:
            print("ERROR: downloading Repo:")
            self._is_supported = False
            print(e.output)

    def removeRepo(self):
        try:
            subprocess.check_output(f'rm -rf {self._repoPath}', stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            print(e.output)

    @property
    def repoUrl(self):
        return self._repoUrl

    @property
    def is_supported(self):
        return self._is_supported

    @property
    def repoName(self):
        return self._repoName

    @property
    def repoPath(self):
        return self._repoPath

    # gets the current version of this repo
    def get_SHA(self):
        if self._repoType == 'git':
            return subprocess.check_output(f'git rev-parse --verify  HEAD', cwd=self._repoPath, text=True,
                                           shell=True).strip()
        elif self._repoType == 'tar.gz':
            subprocess.check_output(f'wget -O {self._repoPath}.tar.gz {self._repoUrl}', stderr=subprocess.STDOUT,
                                    shell=True)
            result = subprocess.check_output(f'shasum {self._repoPath}.tar.gz | cut -d \' \' -f 1',
                                             stderr=subprocess.STDOUT,
                                             text=True,
                                             shell=True)
            # remove temporary
            os.remove("%s.tar.gz" % self._repoPath)
            return result.strip()
        else:
            return None

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
