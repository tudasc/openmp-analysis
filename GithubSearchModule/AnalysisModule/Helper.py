import subprocess
import re

import pandas as pd


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


is_mpi_call_regex = re.compile(r'^((?:call )|(?:[a-z]* ?= ?))?mpi_[a-z_]*\(', re.IGNORECASE)


def get_closing_brace(s, start_pos):
    """
    Returns the position of the corresponding closing brace given a string and the position of an opening brace.

    Parameters:
    s (str): The string to search for the closing brace.
    start_pos (int): The position of the opening brace.

    Returns:
    int: The position of the closing brace, or -1 if not found.
    """
    # get the opening brace character
    open_brace = s[start_pos]

    # determine the closing brace character
    if open_brace == '(':
        close_brace = ')'
    elif open_brace == '[':
        close_brace = ']'
    elif open_brace == '{':
        close_brace = '}'
    else:
        # not a valid opening brace character
        return -1

    # search for the closing brace
    count = 1
    pos = start_pos + 1
    while pos < len(s) and count > 0:
        if s[pos] == open_brace:
            count += 1
        elif s[pos] == close_brace:
            count -= 1
        pos += 1

    # return the position of the closing brace
    if count == 0:
        return pos - 1
    else:
        return -1


def get_parameters(call_remainder_string):
    # basically like
    # params = remainder.split(',')
    # but with proper recognition of inner brace nesting
    split_indices = [0]

    assert call_remainder_string[0] == '('
    assert call_remainder_string[-1] == ')'
    i = 1

    while i < len(call_remainder_string):
        if call_remainder_string[i] == ',':
            split_indices.append(i)
        if call_remainder_string[i] == '(':
            i = get_closing_brace(call_remainder_string, i)
        else:
            i = i + 1

    for i in split_indices[1:]:
        assert call_remainder_string[i] == ','

    params = [call_remainder_string[i + 1:j] for i, j in zip(split_indices, split_indices[1:] + [None])]

    # remove the closing ');' from last parameter
    close_pos = params[-1].rindex(')')
    params[-1] = params[-1][:close_pos]

    return params


# this function splits a line that is a call into the list of parameters given in the call statement
# the first entry in the list (index 0) will be the called function
# empty list if no call was detected in the line
def get_call_with_parmeters(line):
    if '(' in line:
        brace_pos = line.index('(')
        if line.upper().startswith('IF'):
            # if func call is wrapped in an if statement
            brace_pos = line.index('(', brace_pos + 1)

        close_pos = get_closing_brace(line, brace_pos)
        # sometimes the output value is casted into something else (e.g. return (hypre_int) MPI_call(params);)#
        next_brace_pos = line.find('(', close_pos + 1)
        if next_brace_pos != -1:
            brace_pos = next_brace_pos
            close_pos = get_closing_brace(line, brace_pos)

        called_func = line[:brace_pos]
        remainder = line[brace_pos:close_pos + 1]

        # remove something like 'result =' or 'return' or 'call'
        if " " in called_func:
            open_pos = called_func.rindex(' ') + 1  # +1 to remove the space
            prefix = called_func[:open_pos]
            if 'return' in prefix or '=' in prefix or 'if' in prefix or 'CALL' in prefix.upper():
                called_func = called_func[open_pos:]
            else:
                # is declaration not callsite
                return []

        # if there is no space after a cast of result value
        if ")" in called_func:
            open_pos = called_func.rindex(')') + 1  # +1 to remove the brace
            called_func = called_func[open_pos:]

        return [called_func] + [p.strip() for p in get_parameters(remainder)]
    else:
        return []
