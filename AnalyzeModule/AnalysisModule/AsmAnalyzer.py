import os
import sys
import shutil
import math
import subprocess
import angr
from angrutils import *

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


def get_target_addr(inst):
    try:
        tgt = inst.operands[0]
        return int(tgt.split()[0], 16)
    except ValueError:
        # inndirect call or jmp, target depends on register
        return None


def analyze_parallel_region(instructions, blocks, parallel_region_block, blocks_leading_to_recursion_param=[]):
    actualRegion = Region(parallel_region_block.name, parallel_region_block.base_addr)
    blocks_leading_to_recursion = blocks_leading_to_recursion_param + [parallel_region_block]

    instruction_weight = 1.0
    next_meeting_point = []

    for inst in parallel_region_block.instructions:
        if len(next_meeting_point) > 0 and inst.address == next_meeting_point[0]:
            instruction_weight = instruction_weight * 2  # re-union of if
            next_meeting_point.remove(next_meeting_point[0])

        actualRegion.instructionCount += 1 * instruction_weight
        if 'call' in inst.opcode_memonic:
            tgt_addr = get_target_addr(inst)
            if tgt_addr is not None:
                target_block = [b for b in blocks if b.base_addr == tgt_addr][0]
                if target_block in blocks_leading_to_recursion:
                    # RECURSION
                    handleRecursion(actualRegion)
                else:
                    # handle link
                    linkRegion = analyze_parallel_region(instructions, blocks, target_block,
                                                         blocks_leading_to_recursion.copy())
                    if (linkRegion != None):
                        actualRegion.links += linkRegion.links
                        actualRegion.links += 1
                        actualRegion.instructionCount += linkRegion.instructionCount
                        actualRegion.recursions += linkRegion.recursions
                        actualRegion.loops += linkRegion.loops
                        actualRegion.conditionals += linkRegion.conditionals
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
                        actualRegion.conditionals += 1

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
        proj = angr.Project(source, load_options={'auto_load_libs': False})
        cfg = proj.analyses.CFGFast()
        functions = dict(proj.kb.functions)
        openmp_regions = {addr: func for addr, func in functions.items() if '._omp_fn.' in func.name}

        for addr, func in openmp_regions.items():
            print(func)
            print("cyclomatic_complexity:")
            print(func.cyclomatic_complexity)
            plot_cfg(cfg, "cfg", asminst=True, func_addr={func.addr: True}, remove_imports=True, remove_path_terminator=True)

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
