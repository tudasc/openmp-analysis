#!/usr/bin/env python3
# coding: utf-8
from InitializerModule.parser import Parser

import os

import warnings

warnings.simplefilter(action='ignore', category=FutureWarning)

import pandas as pd


def main():
    args = Parser.parseInput()

    if args.mode == 'search':
        command = 'python3 ./SearchModule/searchRepos.py'
        command = command + ' --data_dir ' + args.data_dir
        command = command + ' --searchqueries ' + args.searchqueries
        command = command + ' --codequeries ' + args.codequeries
        command = command + ' --api ' + args.api
        command = command + ' --found_file ' + args.found_file 
        command = command + ' --evaluated_file ' + args.evaluated_file
    elif args.mode == 'analyze':
        assert args.mode == 'analyze'
        command = 'python3 ./AnalyzeModule/analyze.py'
        command = command + ' --data_dir ' + args.built_dir
        command = command + ' --asm_dir ' + args.asm_dir
        command = command + ' --results_dir ' + args.results_dir
        command = command + ' --ignore_endings ' + args.ignore_endings
        command = command + ' --ignore_folders ' + args.ignore_folders
        if(args.keep_data):
            command = command + ' --keep_data'
    else:
        assert args.mode == 'evaluate'
        command = 'python3 ./EvaluateModule/evaluate.py'
        command = command + ' --data_dir ' + args.built_dir
        command = command + ' --results_dir ' + args.result_dir
        command = command + ' --statistics_dir ' + args.statistics_dir
        command = command + ' --evaluated_file ' + args.repos_file
        command = command + ' --pragmas_file ' + args.pragmas_file
        command = command + ' --overhead_high ' + str(args.overhead_high)
        command = command + ' --overhead_low ' + str(args.overhead_low)


    if(args.refresh):
        command = command + ' --refresh'

    os.system(command)


if __name__ == "__main__":
    main()
