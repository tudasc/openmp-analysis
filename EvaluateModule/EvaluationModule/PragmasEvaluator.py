import pandas as pd

class PragmasEvaluator:
    __slots__ = ('_datadir', '_pragmas')

    def __init__(self, datadir, pragmasfile):
        self._datadir = datadir
        file = open(pragmasfile, 'r')
        self._pragmas = file.read().split('\n')
        file.close()

    def __call__(self, code):
        try:
            df = pd.read_csv(self._datadir + code + '/results.csv', header=0)
            pragmas_list = df['openmp_pragma_used']
            dictionary = dict()
            for pragmas in pragmas_list:
                for actual in eval(pragmas):
                    splitted = actual.split('(')
                    if splitted[0] in self._pragmas:
                        if splitted[0] in dictionary:
                            dictionary[splitted[0]] += 1
                        else:
                            dictionary.update({splitted[0]: 1})
            return dictionary
        except Exception:
            print('Evaluating ' + self._datadir + code + '/results.csv threw an Exception!')