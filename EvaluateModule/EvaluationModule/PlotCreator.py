import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def mergeDicToDic(mergeTo, mergeFrom):
    for key, value in mergeFrom.items():
        if key in mergeTo:
            mergeTo[key] = mergeTo.get(key) + value
        else:
            mergeTo.update({key:value})

    return mergeTo

def createBarhPlot(keys, values, color, contrastColor, title, dir, name):
    colors = [contrastColor if ('Overhead' in x) else color for x in keys]

    fig, ax = plt.subplots(figsize=(16,10))
    ax.barh(keys, values, color=colors)
    for s in ['top', 'bottom', 'left', 'right']:
        ax.spines[s].set_visible(False)
    ax.xaxis.set_ticks_position('none')
    ax.yaxis.set_ticks_position('none')
    ax.xaxis.set_tick_params(pad = 5)
    ax.yaxis.set_tick_params(pad = 10)
    ax.grid(visible = True, color ='grey',
            linestyle ='-.', linewidth = 0.5,
            alpha = 0.2)
    ax.invert_yaxis()
    for index, patch in enumerate(ax.patches):
        if(colors[index] == contrastColor):
            plt.text(patch.get_width()+0.2, patch.get_y()+0.65, 
                str(round((patch.get_width()), 2)),
                fontsize = 9,
                color =contrastColor)
        else:
            plt.text(patch.get_width()+0.2, patch.get_y()+0.65, 
                str(round((patch.get_width()), 2)),
                fontsize = 9,
                color ='grey')
    ax.set_title(title,
                loc ='left', )
    
    for index, label in enumerate(ax.get_yticklabels(False)):
        if(colors[index] == contrastColor):
            plt.setp(label, color=colors[index])
        else:
            plt.setp(label, color='grey')

    plt.savefig(dir + name, bbox_inches='tight')
    plt.close()

def createPragmaUsagePlot(dir, df):
    try:
        usedPragmas = dict()
        for index, row in df.iterrows():
            usedPragmas = mergeDicToDic(usedPragmas, row['UsedPragmas'])
        usedPragmas = dict(sorted(usedPragmas.items(), key=lambda item: item[1], reverse=True))

        createBarhPlot(list(usedPragmas.keys()), list(usedPragmas.values()), '#a1c7ed', '#eda1a1', 'Accumulated Pragma Usage', dir, 'used_pragmas.png')
        print('\tCreated Pragma Usage plot.')
    except Exception:
        print('\tCreation of Pragma Usage plot threw an exception... skipping plot.')

def createParallelRegionPlot(dir, df):
    try:
        parallel_regions = dict()
        for index, row in df.iterrows():
            parallel_regions.update({row['Code']:row['ParallelRegions']})
        parallel_regions = dict(sorted(parallel_regions.items(), key=lambda item: item[1], reverse=True))

        createBarhPlot(list(parallel_regions.keys()), list(parallel_regions.values()), '#a1c7ed', '#eda1a1', 'Parallel Regions per project', dir, 'parallel_regions.png')
        print('\tCreated Parallel Regions plot.')
    except Exception:
        print('\tCreation of Parallel Regions plot threw an exception... skipping plot.')    

def createRegionGradePlot(dir, df):
    try:
        codes = []
        veryGood = []
        good = []
        neutral = []
        bad = []
        for index, row in df.iterrows():
            parallelRegions = row['ParallelRegions']
            codes.append(row['Code'])
            veryGood.append(row['VeryGoodRegions']/parallelRegions*100)
            good.append(row['GoodRegions']/parallelRegions*100)
            neutral.append(row['NeutralRegions']/parallelRegions*100)
            bad.append(row['BadRegions']/parallelRegions*100)

        fig, ax = plt.subplots(figsize=(16,10))
        b1 = ax.barh(codes, veryGood, color='#62ab58')

        lefts = veryGood
        b2 = ax.barh(codes, good, left=lefts, color='#87ed79')

        for index, value in enumerate(lefts):
            lefts[index] = lefts[index] + good[index]
        b3 = ax.barh(codes, neutral, left=lefts, color='#edd679')

        for index, value in enumerate(lefts):
            lefts[index] = lefts[index] + neutral[index]
        b4 = ax.barh(codes, bad, left=lefts, color='#ed7a7a')

        ax.legend([b1, b2, b3, b4], ['Very Good', 'Good', 'Neutral', 'Bad'], loc='upper right')

        for s in ['top', 'bottom', 'left', 'right']:
            ax.spines[s].set_visible(False)
        ax.xaxis.set_ticks_position('none')
        ax.yaxis.set_ticks_position('none')
        ax.xaxis.set_tick_params(pad = 5)
        ax.yaxis.set_tick_params(pad = 10)
        ax.grid(visible = True, color ='grey',
                linestyle ='-.', linewidth = 0.5,
                alpha = 0.2)
        ax.invert_yaxis()

        ax.set_title('Region grading per project in %',
                    loc ='left', )
        
        for index, label in enumerate(ax.get_yticklabels(False)):
            plt.setp(label, color='grey')

        plt.savefig(dir + 'region_grades.png', bbox_inches='tight')
        plt.close()
        print('\tCreated Regions Grade plot.')
    except Exception:
        print('\tCreation of Regions Grade plot threw an exception... skipping plot.')

def createRegionGradeTotalPlot(dir, df):
    try:
        parallelRegions = df['ParallelRegions'].sum()
        labels = ['Very Good', 'Good', 'Neutral', 'Bad']
        values = [round(df['VeryGoodRegions'].sum()*100/parallelRegions, 2), round(df['GoodRegions'].sum()*100/parallelRegions, 2), round(df['NeutralRegions'].sum()*100/parallelRegions, 2), round(df['BadRegions'].sum()*100/parallelRegions, 2)]

        fig, ax = plt.subplots(figsize=(16,10))
        ax.bar(labels, values, color=['#62ab58', '#87ed79', '#edd679', '#ed7a7a'])

        for s in ['top', 'bottom', 'left', 'right']:
            ax.spines[s].set_visible(False)
        ax.xaxis.set_ticks_position('none')
        ax.yaxis.set_ticks_position('none')
        ax.xaxis.set_tick_params(pad = 5)
        ax.yaxis.set_tick_params(pad = 10)
        ax.grid(visible = True, color ='grey',
                linestyle ='-.', linewidth = 0.5,
                alpha = 0.2)
        
        for i in range(len(labels)):
            plt.text( i + 0.02, values[i] + 0.5, str(values[i]) + '%', fontsize=15, color='grey', ha= 'center')

        ax.set_title('Region grading in all projects in %',
                    loc ='left', )
        
        for index, label in enumerate(ax.get_yticklabels(False)):
            plt.setp(label, color='grey')

        for index, label in enumerate(ax.get_xticklabels(False)):
            plt.setp(label, color='grey')

        plt.savefig(dir + 'region_grades_total.png', bbox_inches='tight')
        plt.close()
        print('\tCreated Regions Grade total plot.')
    except Exception:
        print('\tCreation of Regions Grade total plot threw an exception... skipping plot.')


def createStarsPlot(dir, df):
    try:
        stars = dict()
        for index, row in df.iterrows():
            stars.update({row['Code']:row['Stars']})
        stars = dict(sorted(stars.items(), key=lambda item: item[1], reverse=True))

        createBarhPlot(list(stars.keys()), list(stars.values()), '#a1c7ed', '#eda1a1', 'Stars per project', dir, 'stars.png')
        print('\tCreated Stars plot.')
    except Exception:
        print('\tCreation of Stars plot threw an exception... skipping plot.')

def createMaximumInstructionsPlot(dir, overheadhigh, overheadlow, df):
    try:
        maxs = dict()
        for index, row in df.iterrows():
            maxs.update({row['Code']:row['MaxInstructions']})
        maxs.update({'Overhead many Threads': overheadhigh, 'Overhead few Threads': overheadlow})
        maxs = dict(sorted(maxs.items(), key=lambda item: item[1], reverse=True))

        createBarhPlot(list(maxs.keys()), list(maxs.values()), '#a1c7ed', '#eda1a1', 'Maximal Instructions in a single parallel region per project', dir, 'maximal_instructions.png')
        print('\tCreated MaxInstructions plot.')
    except Exception:
        print('\tCreation of MaxInstructions plot threw an exception... skipping plot.')

def createAverageInstructionsPlot(dir, overheadhigh, overheadlow, df):
    try:
        avgs = dict()
        for index, row in df.iterrows():
            avgs.update({row['Code']:row['MinInstructions']})
        avgs.update({'Overhead many Threads': overheadhigh, 'Overhead few Threads': overheadlow})
        avgs = dict(sorted(avgs.items(), key=lambda item: item[1], reverse=True))

        createBarhPlot(list(avgs.keys()), list(avgs.values()), '#a1c7ed', '#eda1a1', 'Average Instructions in parallel regions per project', dir, 'average_instructions.png')
        print('\tCreated AvgInstructions plot.')
    except Exception:
        print('\tCreation of AvgInstructions plot threw an exception... skipping plot.')

def createMinimalInstructionsPlot(dir, overheadhigh, overheadlow, df):
    try:
        mins = dict()
        for index, row in df.iterrows():
            mins.update({row['Code']:row['MinInstructions']})
        mins.update({'Overhead many Threads': overheadhigh, 'Overhead few Threads': overheadlow})
        mins = dict(sorted(mins.items(), key=lambda item: item[1], reverse=True))

        createBarhPlot(list(mins.keys()), list(mins.values()), '#a1c7ed', '#eda1a1', 'Minimal Instructions in a single parallel region per project', dir, 'minimal_instructions.png')
        print('\tCreated MinInstructions plot.')
    except Exception:
        print('\tCreation of MinInstructions plot threw an exception... skipping plot.')

class PlotCreator:
    __slots__ = ('_statisticsdir', '_overheadhigh', '_overheadlow')

    def __init__(self, statisticsdir, overheadhigh, overheadlow):
        self._statisticsdir = statisticsdir
        self._overheadhigh = overheadhigh
        self._overheadlow = overheadlow

    def __call__(self, df, evaluatedDf):
        createPragmaUsagePlot(self._statisticsdir, df)
        createParallelRegionPlot(self._statisticsdir, df)
        createRegionGradePlot(self._statisticsdir, df)
        createRegionGradeTotalPlot(self._statisticsdir, df)
        createStarsPlot(self._statisticsdir, df)
        createMaximumInstructionsPlot(self._statisticsdir, self._overheadhigh, self._overheadlow, df)
        createAverageInstructionsPlot(self._statisticsdir, self._overheadhigh, self._overheadlow, df)
        createMinimalInstructionsPlot(self._statisticsdir, self._overheadhigh, self._overheadlow, df)

        return 0