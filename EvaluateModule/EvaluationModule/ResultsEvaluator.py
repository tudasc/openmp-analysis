import re

def extract_parallel_regions(content):
    regions = []

    pattern_region = re.compile(
        r'\| name: (.+)\n\t\t\| start: line (\d+)\n\t\t\| end: line (\d+)\n\t\t\| instructions: (\d+)\n\t\t\| recursions: (\d+)\n\t\t\| loops: (\d+)\n\t\t\| conditionals: (\d+)\n\t\t\| links: (\d+)', re.MULTILINE
    )

    region_matches = pattern_region.finditer(content)

    for region_match in region_matches:
        region_info = {
                'instructions': int(region_match.group(4)),
                'recursions': int(region_match.group(5)),
                'loops': int(region_match.group(6)),
                'conditionals': int(region_match.group(7)),
                'links': int(region_match.group(8))
            }
        regions.append(region_info)

    return regions

def extract_information(regions, overheadHigh, overheadLow):
    data = dict()
    data.update({'ParallelRegions' : len(regions)})

    instructionCount = 0
    recursionCount = 0
    loopCount = 0
    conditionalCount = 0
    linkCount = 0
    imax = 0
    imin = float('inf')
    veryGoodRegions = 0
    goodRegions = 0
    neutralRegions = 0
    badRegions = 0
    for region in regions:
        instructions = region['instructions']
        imax = max(imax, instructions)
        imin = min(imin, instructions)
        instructionCount = instructionCount + instructions
        recursionCount = recursionCount + region['recursions']
        loopCount = loopCount + region['loops']
        conditionalCount = conditionalCount + region['conditionals']
        linkCount = linkCount + region['links']
        if(instructions >= 5*overheadHigh):
            veryGoodRegions += 1
        elif(instructions >= 5*overheadLow):
            goodRegions += 1 
        elif(instructions >= 2*overheadLow):
            neutralRegions += 1 
        else:
            badRegions += 1
    
    data.update({'VeryGoodRegions' : veryGoodRegions, 'GoodRegions' : goodRegions, 'NeutralRegions' : neutralRegions, 'BadRegions' : badRegions ,'AvgInstructions' : int(instructionCount/len(regions)), 'MaxInstructions':imax,'MinInstructions': imin, 'AvgRecursions' : int(recursionCount/len(regions)), 'AvgLoops' : int(loopCount/len(regions)), 'AvgConditionals' : int(conditionalCount/len(regions)), 'AvgLinks' : int(linkCount/len(regions))})

    return data

class ResultsEvaluator:
    __slots__ = ('_resultsdir', '_overheadhigh', '_overheadlow')

    def __init__(self, resultsdir, overheadhigh, overheadlow):
        self._resultsdir = resultsdir
        self._overheadhigh = overheadhigh
        self._overheadlow = overheadlow

    def __call__(self, resultsfile):
        with open(self._resultsdir + '/' + resultsfile, 'r') as file:
            content = file.read()
            regions = extract_parallel_regions(content)
            return extract_information(regions, self._overheadhigh, self._overheadlow)