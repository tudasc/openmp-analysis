import os
import pandas as pd
import tqdm
import multiprocessing as mp
from EvaluationModule.ListEvaluator import ListEvaluator
from EvaluationModule.ResultsEvaluator import ResultsEvaluator
from EvaluationModule.PragmasEvaluator import PragmasEvaluator
from EvaluationModule.PlotCreator import PlotCreator
from EvaluationModule.StatisticalEvaluator import StatisticalEvaluator

def evaluate_repo_single_arg(args):
    return evaluate_repo(args[0], args[1], args[2], args[3])
    

def evaluate_repo(resultsfile, listevaluator, resultsevaluator, pragmasevaluator):
    code = resultsfile[ :len(resultsfile)-len('.results')]
    try:
        repo_data = dict()
        repo_data.update(listevaluator(code))
        repo_data.update({'UsedPragmas' : pragmasevaluator(code)})
        repo_data.update({'PragmaTotal' : sum(repo_data['UsedPragmas'].values())})
        repo_data.update(resultsevaluator(resultsfile))

        return repo_data
    except Exception:
        print("Evaluation of repo with name: " + code + ", aborted, because it threw an Exception!")
        return None

class EvaluationManager:
    __slots__ = ('_resultsdir', '_totalresultsfile', '_statisticresultsfile', '_refresh', '_listevaluator', '_resultsevaluator', '_pragmasevaluator', '_statisticalevaluator', '_plotcreator', '_evaluatedDf')

    def __init__(self, datadir, resultsdir, statisticsdir, evaluatedfile, pragmasfile, overheadhigh, overheadlow, refresh=False):
        assert os.path.isdir(datadir) and 'The path where the repositories are lying must exist'
        assert os.path.isdir(resultsdir) and 'The path where the result files are lying must exist'
        assert os.path.exists(evaluatedfile) and 'The given evaluated file does not exist'
        assert os.path.exists(pragmasfile) and 'The given pragmas file does not exist'
        if(not os.path.isdir(statisticsdir)):
            os.mkdir(statisticsdir)   
        if(datadir[-1] != '/'):
            datadir = datadir + '/'
        if(resultsdir[-1] != '/'):
            resultsdir = resultsdir + '/'
        if(statisticsdir[-1] != '/'):
            statisticsdir = statisticsdir + '/'

        self._resultsdir = resultsdir
        self._totalresultsfile = statisticsdir + '/total_results.csv'
        self._statisticresultsfile = statisticsdir + '/statistic_results.csv'
        self._refresh = refresh
        self._evaluatedDf = pd.read_csv(evaluatedfile, header=0, index_col=0)
        self._listevaluator = ListEvaluator(self._evaluatedDf)
        self._resultsevaluator = ResultsEvaluator(resultsdir, overheadhigh, overheadlow)
        self._pragmasevaluator = PragmasEvaluator(datadir, pragmasfile)
        self._statisticalevaluator = StatisticalEvaluator()
        self._plotcreator = PlotCreator(statisticsdir, overheadhigh, overheadlow)

    # perform the evaluation
    def __call__(self):
        if(self._refresh or not os.path.exists(self._totalresultsfile)):
            with mp.Pool() as pool:
                param_list = [(file, self._listevaluator, self._resultsevaluator, self._pragmasevaluator) for
                            file in
                            os.listdir(self._resultsdir)]
                evaluated_repos = list(tqdm.tqdm(pool.imap_unordered(evaluate_repo_single_arg, param_list), total=len(param_list)))
            
            df = pd.DataFrame.from_records(list(filter(lambda item: item is not None, evaluated_repos)))
            df.sort_values(by=['Stars'], inplace=True, ascending=False)
            df.reset_index(drop=True, inplace=True)
            df.to_csv(self._totalresultsfile)
            print('Created total results file.')
        else:
            df = pd.read_csv(self._totalresultsfile, header=0, index_col=0)
            print('Read total results file.')

        if(self._refresh or not os.path.exists(self._statisticresultsfile)):
            stat = self._statisticalevaluator(df)
            stat.to_csv(self._statisticresultsfile)
            print('Created statistic results file.')
        else:
            stat = pd.read_csv(self._statisticresultsfile, header=0, index_col=0)
            print('Read statistic results file.')

        print('Creating plots...')
        self._plotcreator(df, self._evaluatedDf)
        print('Finished creating plots.')

        return 0