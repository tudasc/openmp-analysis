from InitializerModule.parser import Parser
from EvaluationModule.EvaluationManager import EvaluationManager
import os

def main():
    args = Parser.parseInput()

    evaluator = EvaluationManager(args.data_dir, args.results_dir, args.statistics_dir, args.evaluated_file, args.pragmas_file, args.overhead_high, args.overhead_low,args.refresh)

    evaluator()

if __name__ == '__main__':
    main()