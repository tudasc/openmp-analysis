import os
import sys
import shutil
import math
import subprocess

from AnalyzeModule.AnalysisModule.Region import Region

# from AnalysisModule.Region import Region

# bounds checking jump
list_of_prefixes = ["bnd"]


# helpe function that also works for empty strings
def split_str_retrun_empty(s, delim):
    if s == "":
        return "", ""
    result = s.split(delim, maxsplit=1)
    if len(result) == 1:
        return result[0], ""
    else:
        return result


class ASMInstruction:
    # TODO documentation of fields
    hex_instruction = None
    region_name = None
    block_name = None
    address = None
    opcode_memonic = None
    operands = []
    prefix = None

    def __init__(self, line, region, block):
        self.region_name = region
        self.block_name = block
        # parse line
        address, reminder = line.split(":", maxsplit=1)
        self.address = int(address, 16)

        reminder = reminder.lstrip()  # remove leading tab
        hex_inst_str, reminder = split_str_retrun_empty(reminder, '\t')
        self.hex_instruction = hex_inst_str.replace(' ', '')

        prefix, reminder = split_str_retrun_empty(reminder, ' ')
        if prefix in list_of_prefixes:
            self.prefix = prefix
        else:
            # not a prefix: use original reminder
            reminder = prefix + ' ' + reminder

        memonic, reminder = split_str_retrun_empty(reminder, ' ')
        self.opcode_memonic = memonic
        no_comment, comment = split_str_retrun_empty(reminder, '#')

        if no_comment != "":
            self.operands = [op.strip() for op in no_comment.split(',')]


class ASMBlock:
    name = None
    base_addr = None
    instructions = []

    def __init__(self, name, base_addr, instructions):
        self.name = name
        self.base_addr = int(base_addr, 16)
        self.instructions = instructions
        for i in instructions:
            assert i.block_name == name


def handleRecursion(region):
    region.recursions += 1


def handleLoop(instructions, blocks, stadt_address, end_address, region):
    region.loops += 1
    region.instructionCount += 399


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


def get_target_addr(inst):
    tgt = inst.operands[0]
    return int(tgt.split()[0], 16)


def analyze_parallel_region(instructions, blocks, parallel_region_block):
    actualRegion = Region(parallel_region_block.name, parallel_region_block.base_addr)
    blocks_leading_to_recursion = [parallel_region_block]

    instruction_weight = 1.0
    next_meeting_point = []

    for inst in parallel_region_block.instructions:
        if len(next_meeting_point) > 0 and inst.address == next_meeting_point[0]:
            instruction_weight = instruction_weight * 2  # re-union of if
            next_meeting_point.remove(next_meeting_point[0])

        actualRegion.instructionCount += 1 * instruction_weight
        if 'call' in inst.opcode_memonic:
            tgt_addr = get_target_addr(inst)
            target_block = [b for b in blocks if b.base_addr == tgt_addr][0]
            if target_block in blocks_leading_to_recursion:
                # RECURSION
                handleRecursion(actualRegion)
            else:
                # TODO handle link
                continue
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
        # jump
        if inst.opcode_memonic.startswith('j'):
            tgt_addr = get_target_addr(inst)
            if tgt_addr < inst.address:
                # backward jump
                # LOOP
                # TODO handle Loop
                handleLoop(instructions, blocks, tgt_addr, inst.address, actualRegion)
            else:
                if inst.opcode_memonic == "jmp":
                    # unconditional branch
                    next_meeting_point.append(tgt_addr)
                    # before, the two branches will not meet
                    next_meeting_point = [addr for addr in next_meeting_point if addr >= tgt_addr]
                    assert sorted(next_meeting_point) == next_meeting_point  # should still be sorted
                    pass
                else:
                    # forward jump
                    # IF
                    # ecch branhc has same likeleyhood
                    instruction_weight = instruction_weight * 0.5
                    next_meeting_point.append(tgt_addr)

    return actualRegion


# Find all regions that begin with word, including their links
def findRegionsBeginningWith(instructions, blocks, word, dictionary, onlyFirst, backLinkNames):
    foundRegions = []
    for b in blocks:
        if word in b.name:
            print("found Parallel Region")
            print(b.name)

            foundRegions.append(analyze_parallel_region(instructions, blocks, b))

    return foundRegions


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
    def __call__(self, source, outfile):
        instructions, blocks = parse_asm_file(source)

        regionsDic = dict()

        parallel_regions = findRegionsBeginningWith(instructions, blocks, '._omp_fn.', regionsDic, False, [])

        with open('%s' % outfile, 'w') as outfile:
            outfile.write(os.path.basename(source) + ': \n')
            outfile.write('\tamount of parallel regions: ' + str(len(parallel_regions)) + '\n')
            if (len(parallel_regions) > 0):
                outfile.write('\tregions: \n')
                writeRegions('\t', parallel_regions, outfile)
            outfile.write('\n')

        # if(not keep_data):
        #    shutil.rmtree(source)

        return 0


# TODO documentation
# returns a list of ParseResults
# they contain the following fields:
# address
# section if a section, else:
# hex instruction
# opcode memonic
# operands (as list)

def parse_asm_file(fname):
    # the language setting is important, so that we can check that the line
    # <filename>:     file format elf64-x86-64
    # is present
    disassembly = subprocess.check_output(['objdump', '-d', fname], env={"LANG": "EN_US"},
                                          text=True)
    if not "file format elf64-x86-64" in disassembly:
        assert False and "Not a valid assembly file"

    instructions = []
    instructions_in_block = []
    blocks = []
    block = ""
    block_base_addr = ""
    region = ""
    # ignore the fille format line
    for line in disassembly.splitlines()[2:]:
        if line.startswith(' '):
            inst = ASMInstruction(line, region, block)
            instructions.append(inst)
            instructions_in_block.append(inst)
        elif line.startswith("Disassembly of section"):
            region = line[len("Disassembly of section"):-1]
        elif line == "":
            pass  # ignore
        else:
            # end block
            if block != "":
                blocks.append(ASMBlock(block, block_base_addr, instructions_in_block))
                instructions_in_block = []
            block_base_addr, block = line.split(' ')
    if block != "":
        blocks.append(ASMBlock(block, block_base_addr, instructions_in_block))

    return instructions, blocks
