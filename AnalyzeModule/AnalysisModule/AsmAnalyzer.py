import os
import sys
import shutil
import math
from binaryornot.check import is_binary


# from AnalysisModule.Region import Region

def checkLocationForAssemblerFiles(src):
    files = []
    for file in os.listdir(src):
        if os.path.exists(src + file + '/'):
            newsrc = src + file + '/'
            files.extend(checkLocationForAssemblerFiles(newsrc))
        elif file.endswith('.ASM'):
            files.append(src + file)
        elif file.endswith('.asm'):
            files.append(src + file)
    return files


def handleRecursion(region):
    region.recursions += 1


def handleLoop(region, fromLine, toLine):
    region.loops += 1
    return 399


def handleIf(file, fileContent, region, toLine, dictionary, backLinkNames):
    instructionCount = 0
    lineOffset = 0
    for lineNumber, line in enumerate(fileContent):
        splitted = line.split()
        if (len(splitted) == 0 or (len(splitted) > 0 and splitted[0].removesuffix(':') == toLine)):
            region.conditionals += 1
            return math.floor(instructionCount / 2), lineOffset + lineNumber + 1
        else:
            instructionCount += 1
            if (len(splitted) > 2):
                if ('call' in splitted[-3]):
                    if (splitted[len(splitted) - 1] in backLinkNames):
                        handleRecursion(region)
                    else:
                        linkWord = splitted[len(splitted) - 1]
                        linkRegion = findRegionsBeginningWith(file, linkWord, dictionary, True, backLinkNames.copy())
                        if (linkRegion != None and len(linkRegion) == 1):
                            region.links += linkRegion[0].links
                            region.links += 1
                            instructionCount += linkRegion[0].instructionCount
                            region.recursions += linkRegion[0].recursions
                            region.loops += linkRegion[0].loops
                            region.conditionals += linkRegion[0].conditionals

                if (splitted[len(splitted) - 3].startswith('j')):
                    newFromLine = splitted[0].removesuffix(':')
                    newToLine = splitted[len(splitted) - 2]
                    if (int(newToLine, 16) < int(newFromLine, 16)):
                        instructionCount += handleLoop(region, newFromLine, newToLine)
                    else:
                        if (newToLine <= toLine):
                            result = handleIf(file, fileContent, region, newToLine, dictionary, backLinkNames.copy())
                            instructionCount += result[0]
                            lineOffset += result[1]
                            instructionCount += 1
                            if (newToLine == toLine):
                                region.conditionals += 1
                                return math.floor(instructionCount / 2), lineOffset + lineNumber + 1


# Find all regions that begin with word, including their links
def findRegionsBeginningWith(file, word, dictionary, onlyFirst, backLinkNames):
    if (onlyFirst):
        if (word in dictionary):
            return [].append(dictionary[word])

    lineOffset = 0
    foundRegions = []
    actualRegion = None
    with open(file, 'r') as fileContent:
        for lineNumber, line in enumerate(fileContent):
            lineNumber += lineOffset
            if (actualRegion == None):
                if (len(line.split()) == 2 and word in line):
                    name = line.split()[1].removesuffix(':')
                    backLinkNames.append(name)
                    actualRegion = Region(name, lineNumber)
            else:
                if (len(line.strip()) == 0):
                    actualRegion.end = lineNumber
                    if (actualRegion.recursions != 0):
                        actualRegion.instructionCount = actualRegion.instructionCount * actualRegion.recursions
                    foundRegions.append(actualRegion)
                    if (onlyFirst):
                        break
                    actualRegion = None
                    backLinkNames = []
                else:
                    actualRegion.instructionCount += 1
                    splitted = line.split()
                    if (len(splitted) > 2):
                        if ('call' in splitted[-3]):
                            if (splitted[len(splitted) - 1] in backLinkNames):
                                handleRecursion(actualRegion)
                            else:
                                linkWord = splitted[len(splitted) - 1]
                                linkRegion = findRegionsBeginningWith(file, linkWord, dictionary, True,
                                                                      backLinkNames.copy())
                                if (linkRegion != None and len(linkRegion) == 1):
                                    actualRegion.links += linkRegion[0].links
                                    actualRegion.links += 1
                                    actualRegion.instructionCount += linkRegion[0].instructionCount
                                    actualRegion.recursions += linkRegion[0].recursions
                                    actualRegion.loops += linkRegion[0].loops
                                    actualRegion.conditionals += linkRegion[0].conditionals

                        if (splitted[len(splitted) - 3].startswith('j')):
                            fromLine = splitted[0].removesuffix(':')
                            toLine = splitted[len(splitted) - 2]
                            if (int(toLine, 16) < int(fromLine, 16)):
                                actualRegion.instructionCount += handleLoop(actualRegion, fromLine, toLine)
                            else:
                                result = handleIf(file, fileContent, actualRegion, toLine, dictionary,
                                                  backLinkNames.copy())
                                actualRegion.instructionCount += result[0]
                                lineOffset += result[1]
                                actualRegion.instructionCount += 1
            if (onlyFirst):
                dictionary.update({word: actualRegion})
    return foundRegions


def findWordOccurences(file, word):
    with open(file, 'r') as fileContent:
        foundLines = []
        for lineNumber, line in enumerate(fileContent):
            if word in line:
                foundLine = []
                foundLine.append(lineNumber)
                foundLine.append(line)
                foundLines.append(foundLine)
        return foundLines


# write all given regions into outfile
def writeRegions(basePrint, regions, outfile):
    for region in regions:
        outfile.write(basePrint + '\t____________________________\n')
        outfile.write(basePrint + '\t| name: ' + region.name + '\n')
        outfile.write(basePrint + '\t| start: line ' + str(region.start + 1) + '\n')
        outfile.write(basePrint + '\t| end: line ' + str(region.end) + '\n')
        outfile.write(basePrint + '\t| instructions: ' + str(region.instructionCount) + '\n')
        outfile.write(basePrint + '\t| recursions: ' + str(region.recursions) + '\n')
        outfile.write(basePrint + '\t| loops: ' + str(region.loops) + '\n')
        outfile.write(basePrint + '\t| conditionals: ' + str(region.conditionals) + '\n')
        outfile.write(basePrint + '\t| links: ' + str(region.links) + '\n')
        outfile.write(basePrint + '\t‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\n')


class AsmAnalyzer:
    __slots__ = ()

    def __init__(self):
        pass

    # perform the analyses
    def __call__(self, source, outfile, keep_data=False):
        files = checkLocationForAssemblerFiles(source)

        # Checking if the folder contains no .ASM files.
        if len(files) == 0:
            print('No .ASM or .asm files exist in folder specified and it\'s subfolders')
            sys.exit()

        outfile = open('%s' % outfile, 'w')

        for file in files:

            regionsDic = dict()

            parallel_regions = findRegionsBeginningWith(file, '._omp_fn.', regionsDic, False, [])

            outfile.write(os.path.basename(file) + ': \n')
            outfile.write('\tamount of parallel regions: ' + str(len(parallel_regions)) + '\n')
            if (len(parallel_regions) > 0):
                outfile.write('\tregions: \n')
                writeRegions('\t', parallel_regions, outfile)
            outfile.write('\n')

        # if(not keep_data):
        #    shutil.rmtree(source)

        return 0


import subprocess

from pyparsing import Word, hexnums, WordEnd, Optional, alphas, alphanums, restOfLine

def parse_asm_file( fname):

    # the language setting is important, so that we can check that the line
    # <filename>:     file format elf64-x86-64
    # is present
    disassembly = subprocess.check_output(['objdump', '-d', fname], env={"LANG": "EN_US"},
                                     text=True)
    if not "file format elf64-x86-64" in disassembly:
        assert False and "Not an assembly file"


    hex_integer = Word(hexnums) + WordEnd()  # use WordEnd to avoid parsing leading a-f of non-hex numbers as a hex
    line_parser = (Optional((Word(hexnums)('address'))
                            # an instruction:
                            + Optional(':' + (hex_integer * (1,))("hex_instruction") +
                                       Word(alphas, alphanums)("opcode_memonic") +
                                       Optional(((Word(alphanums + "%$()") + Optional(",")) * (1,))("operands")) +
                                       Optional("#" + restOfLine("comment")))
                            # a section name
                            + Optional("<" + (Word(alphanums + "_.@"))("section") + ">")))

    return [line_parser.parse_string(s) for s in disassembly.splitlines()]


def main():
    fname = "/home/tim/openmp_usage_analysis/example/a.out"
    result = parse_asm_file(fname)
    print(result)

    for line in result:
        if "opcode_memonic" in line:
            print(line.opcode_memonic)



if __name__ == "__main__":
    main()
