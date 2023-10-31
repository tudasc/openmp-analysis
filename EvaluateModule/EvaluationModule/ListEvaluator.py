import pandas as pd

class ListEvaluator:
    __slots__ = ('_data')

    def __init__(self, data):
        self._data = data

    def __call__(self, code):
        data = dict()

        row = self._data.loc[self._data['Code'] == code.replace('.', '/')].iloc[0]

        data.update({'Code': row['Code'], 'Language' : row['Language'], 'Type' : row['Type'], 'Stars' : row['Stars'], 'PushDate' : row['PushDate']})

        return data