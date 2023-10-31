import pandas as pd

def evaluateColumn(df, columnname):
    column = df[columnname]
    result = dict()
    result.update({'ColumnName':columnname, 'Mean':column.mean(), 'StandardDeviation':column.std(), 'Maximum':column.max(), 'Minimum':column.min(), '25th Percentile':column.quantile(q=0.25), 'Median':column.median(), '75th Percentile':column.quantile(q=0.75)})
    return result



class StatisticalEvaluator:
    __slots__ = ()

    def __call__(self, df):
        rows = []
        rows.append(evaluateColumn(df, 'Stars'))
        rows.append(evaluateColumn(df, 'PragmaTotal'))
        rows.append(evaluateColumn(df, 'ParallelRegions'))
        rows.append(evaluateColumn(df, 'VeryGoodRegions'))
        rows.append(evaluateColumn(df, 'GoodRegions'))
        rows.append(evaluateColumn(df, 'NeutralRegions'))
        rows.append(evaluateColumn(df, 'BadRegions'))
        rows.append(evaluateColumn(df, 'AvgInstructions'))
        rows.append(evaluateColumn(df, 'MaxInstructions'))
        rows.append(evaluateColumn(df, 'MinInstructions'))
        rows.append(evaluateColumn(df, 'AvgRecursions'))
        rows.append(evaluateColumn(df, 'AvgLoops'))
        rows.append(evaluateColumn(df, 'AvgConditionals'))
        rows.append(evaluateColumn(df, 'AvgLinks'))

        return pd.DataFrame.from_records(rows)
