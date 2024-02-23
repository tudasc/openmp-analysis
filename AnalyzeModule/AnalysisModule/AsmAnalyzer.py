import itertools
import os
import sys
import shutil
import math
import subprocess
from collections import OrderedDict
import matplotlib.pyplot as plt

import re

import angr
import networkx
import networkx as nx
from angrutils import plot_cfg
from networkx import NetworkXError

# from angrutils import *

from AnalyzeModule.AnalysisModule.Region import Region

# from AnalysisModule.Region import Region


hex_pattern = re.compile("0[xX][0-9a-fA-F]+")

# bounds checking jump
list_of_prefixes = ["bnd"]


# prune the CFG to remove all "call" and "return" edges, as they will be handles in the callgraph in our analysis
# returns pruned copy
def get_pruned_cfg(graph_in):
    graph = graph_in.copy()
    # collect edges to remove
    to_remove = []
    for u, v, kind in graph.edges(data="jumpkind"):
        if kind == 'Ijk_Ret' or kind == 'Ijk_Call':
            to_remove.append((u, v))

    for edge in to_remove:
        graph.remove_edge(edge[0], edge[1])
    return graph


def is_register(reg):
    return reg in ['rax', 'rbx', 'rcx', 'rsp', 'rbp', 'rdi', 'rsi', 'rdx',
                   'eax', 'ebx', 'ecx', 'esp', 'ebp', 'edi', 'esi', 'edx',
                   'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


class OpenMPRegionAnalysis(angr.Analysis):

    def __init__(self, option="some_option"):
        self.option = option
        self.cfg = self.project.analyses.CFGFast(normalize=True)
        # detect loops
        self.per_function_cfg = get_pruned_cfg(self.cfg.graph)
        self.loops = list(nx.simple_cycles(self.per_function_cfg))

        self.callgraph = self.kb.callgraph
        # detect recursion
        self.callgraph_cycles = list(nx.simple_cycles(self.callgraph))

        # cache the analyzed functions
        self.function_analysis_result_cache = {}

        # perform analysis
        self.result = []
        self.run()

    def handleRecursion(self, region):
        region.recursions += 1

    def dominates(self, u, v, im_dominators):
        prev_node = v
        cur_node = im_dominators[v]
        while prev_node != cur_node:
            if cur_node == u:
                return True  # found u in domtree
            # go one lvl up in the domtree
            prev_node = cur_node
            cur_node = im_dominators[prev_node]

        return False

    def get_loop_guard(self, loop, this_function_cfg, entry_node):
        # the loop guard block dominates all loop blocks
        im_dominators = networkx.immediate_dominators(this_function_cfg, entry_node)

        guards = []
        for candidate in loop:
            is_entry = True

            for bbb in loop:
                if self.dominates(candidate, bbb, im_dominators):
                    is_entry = False
                    break
            if is_entry:
                guards.append(candidate)
        if len(guards) == 1:
            guard = self.project.factory.block(guards[0].addr)
            # check if it is a conditional jmp
            if guard.disassembly.insns[-1].mnemonic.startswith('j') and guard.disassembly.insns[-1].mnemonic != 'jmp':
                return guard

        # not found
        return None

    # returns set of addresses of each instruction in the function that we know to be based on thread_num
    def get_instructions_based_on_thread_num(self, REMOVE_PARAM, this_function_loop_free_cfg, entry_node):
        return_register = 'eax'  # may be architecture specific
        try:
            thread_num_func = self.kb.functions['omp_get_thread_num']
        except KeyError:
            return set()  # empty

        result = set()

        to_visit = dict()
        to_add = dict()  # BFS
        visited = set()
        # find calls to omp_get_thread_num
        for bb_addr in this_function_loop_free_cfg:
            for tgt, jmp_kind in self.cfg.get_successors_and_jumpkind(bb_addr):
                if jmp_kind == 'Ijk_Call':
                    tgt_func = self.kb.functions.get_by_addr(tgt.addr)
                    if tgt_func == thread_num_func:
                        bb = self.project.factory.block(bb_addr.addr)
                        terminator = bb.disassembly.insns[-1]
                        assert terminator.mnemonic == "call"
                        print(terminator)
                        result.add(terminator)
                        # move from there
                        tainted_registers = {return_register}
                        ret_blocks = list(this_function_loop_free_cfg.neighbors(bb_addr))
                        assert len(ret_blocks) == 1
                        ret_block = ret_blocks[0]
                        assert ret_block not in to_visit
                        to_visit[ret_block] = tainted_registers.copy()
                        visited.add(bb_addr)

        while not len(to_visit) == 0 or not len(to_add) == 0:
            if len(to_visit) == 0:
                to_visit = to_add.copy()
                to_add.clear()

            bb_addr = list(to_visit.keys())[0]
            tainted_registers = to_visit[bb_addr]
            to_visit.pop(bb_addr)
            # only if all incoming edges are visited
            incoming_visited = True
            for inc in this_function_loop_free_cfg.predecessors(bb_addr):
                if inc not in visited:
                    incoming_visited = False
                    break
            if not incoming_visited:
                if not len(to_visit) == 0 and len(to_add) == 0:  # avoid endless recursion
                    # TODO there exist other possibilities of endless recursion
                    # to be visitied later
                    if bb_addr in to_add:
                        to_add[bb_addr] = tainted_registers.intersection(to_add[bb_addr])
                    else:
                        to_add[bb_addr] = tainted_registers.copy()
                    continue
            bb = self.project.factory.block(bb_addr.addr)
            #TODO debugg here with debugger
            for inst in bb.disassembly.insns:
                operands = inst.op_str.split(',')
                if len(operands) == 2:
                    if operands[0].strip() in tainted_registers:
                        if not inst.mnemonic == "cmp":
                            # register overwritten
                            # this is the conservative method anything written into this register marks it as not dependent on thread num anymore
                            # if e.g. another dependant value gets moved here, it could still be tainted
                            # but this requires more logic to e.g. distinguish it from "xor eax,eax" here the result is not dependant anymore
                            tainted_registers.remove(operands[0].strip())

                    if operands[1].strip() in tainted_registers:
                        print(inst)
                        result.add(inst)
                        if is_register(operands[0].strip()):
                            tainted_registers.add(operands[0].strip())

                elif len(operands) == 1:
                    if inst.mnemonic == 'call':
                        if return_register in tainted_registers:
                            tainted_registers.remove(return_register)
                    if operands[0].strip() in tainted_registers:
                        tainted_registers.remove(operands[0].strip())
                        # remove, may be written (e.g. pop)
                else:
                    print(inst)
                    if inst.mnemonic == "ret":
                        continue  # end of this branch
                    elif inst.mnemonic == "cdq":
                        if 'edx' in tainted_registers:
                            # overwritten
                            tainted_registers.remove('edx')
                    else:
                        assert False and "operation not supported"

            # end for insts

            for succ in this_function_loop_free_cfg.successors(bb_addr):
                if succ in to_visit:
                    to_visit[succ] = tainted_registers.intersection(to_visit[succ])
                elif succ in to_add:
                    to_add[succ] = tainted_registers.intersection(to_add[succ])
                else:
                    if len(tainted_registers) > 0:  # abort early if nothing more to do
                        to_add[succ] = tainted_registers.copy()

        assert False
        return result

    def handleLoop(self, loop, this_function_cfg, this_function_loop_free_cfg, entry_node, region):
        # try to get trip count of loop

        trip_count_guess = 'DEFAULT'

        guard_block = self.get_loop_guard(loop, this_function_cfg, entry_node)

        if guard_block is not None:
            if guard_block.instructions >= 2:  # has another instruction
                if guard_block.disassembly.insns[-2].mnemonic == "cmp":
                    cmp = guard_block.disassembly.insns[-2]
                    print(cmp)
                    print(cmp.op_str)
                    print(type(cmp))
                    # found the loops cmp instruction
                    # check if it has a constant value
                    operand_1 = cmp.op_str.split(',')[0].strip()
                    operand_2 = cmp.op_str.split(',')[1].strip()
                    print(operand_2)
                    as_int = None
                    try:
                        as_int = int(operand_2)  # decimal constant

                    except ValueError:
                        pass
                    if hex_pattern.match(operand_2):  # is hexnum
                        as_int = int(operand_2[2:], 16)
                    if as_int is not None:
                        print("Found Constant Trip count of loop: %d" % int(as_int))
                        # check if other opreand is register and incremented by 1 every loop trip
                        if is_register(operand_1):
                            for bb_addr in loop:
                                bb = self.project.factory.block(bb_addr.addr)
                                for inst in bb.disassembly.insns:
                                    if inst.mnemonic == 'add':
                                        print(inst.op_str.split(',')[0].strip())
                                        if inst.op_str.split(',')[0].strip() == operand_1:
                                            if inst.op_str.split(',')[1].strip() == '1':
                                                # found increment by 1
                                                trip_count_guess = int(as_int)
                                                break
                    # end if as_int not None

                    # check if val is known to be based of num_threads
                    # TODO optimization: dont calculate the set several times for multiple loops
                    if cmp in self.get_instructions_based_on_thread_num(this_function_cfg, this_function_loop_free_cfg,
                                                                        entry_node):
                        assert trip_count_guess == 'DEFAULT'
                        trip_count_guess = 'DEPEND_ON_THREAD_NUM'
                    # pass

        region.loops += 1

        if trip_count_guess == 'DEFAULT':
            trip_count_guess = 3  # TODO should be a global parameter
        return trip_count_guess

    # calculate weight of each block (probability of execution ignoring loops)
    # with each branch having equal probability
    def get_block_weight(self, loop_free_cfg, entry_node):
        assert len(list(nx.simple_cycles(loop_free_cfg))) == 0  # no cycles
        result = {node: 0.0 for node in loop_free_cfg.nodes}
        result[entry_node] = 1.0

        to_visit = {entry_node}
        to_add = set()  # to implement BFS
        visited = set()

        while len(to_visit) > 0:
            node = to_visit.pop()
            for pred in loop_free_cfg.predecessors(node):
                if pred not in visited:
                    # not all incoming edges where visited
                    to_add.add(node)  # need to re-visit in next BFS wave
                    continue
            visited.add(node)
            if node in to_add:
                to_add.remove(node)  # no endless recursion
            num_successors = len(loop_free_cfg.succ[node])
            for succ in loop_free_cfg.succ[node]:
                to_add.add(succ)
                # propagate probability
                result[succ] += result[node] * (1.0 / num_successors)

            if len(to_visit) == 0:
                to_visit = to_add.copy()
                to_add.clear()

        return result

    # remove all loop back edges from cfg
    # iterative algorithm: remove the edge that is included in most loops, but only if all nodes are still reachable, until no more loops remain
    def remove_back_edges(self, this_function_cfg, entry_node):
        result = this_function_cfg.copy()
        reachable = {entry_node} | networkx.descendants(this_function_cfg,
                                                        entry_node)
        assert reachable == set(this_function_cfg.nodes)

        # TODO: assert that number of loops decreases each step?
        loops = list(networkx.simple_cycles(result))
        while len(loops) > 0:
            removal_candidates = {}
            # collect removal candidates
            for loop in loops:
                for i in range(len(loop) - 1):
                    if (loop[i], loop[i + 1]) not in removal_candidates:
                        removal_candidates[(loop[i], loop[i + 1])] = 0
                    removal_candidates[(loop[i], loop[i + 1])] += 1
            # sort by number of cycles in each node
            removal_candidates = dict(sorted(removal_candidates.items(), key=lambda item: item[1]))
            # try removal
            for edge, _ in removal_candidates.items():
                result.remove_edge(edge[0], edge[1])
                reachable = {entry_node} | networkx.descendants(this_function_cfg,
                                                                entry_node)
                if not reachable == set(this_function_cfg.nodes):
                    # removal partitioned graph
                    result.add_edge(edge[0], edge[1])
                else:
                    # found edge to remove
                    break
            # check for other loops
            loops = list(networkx.simple_cycles(result))
        return result

    def analyze_function(self, func):
        if func in self.function_analysis_result_cache:
            return self.function_analysis_result_cache[func]

        # initialize empty new region
        current_region = Region(func.name, func.addr)

        function_entry_cfg_node = self.cfg.get_node(func.addr)
        this_function_cfg = networkx.subgraph(self.per_function_cfg,
                                              {function_entry_cfg_node} | networkx.descendants(self.per_function_cfg,
                                                                                               function_entry_cfg_node))
        # remove all back edges from cfg to approximate out the branch nesting level of each block
        loop_free_cfg = self.remove_back_edges(this_function_cfg, function_entry_cfg_node)
        # end for each block

        # instruction weight of each block
        block_weights = self.get_block_weight(loop_free_cfg, function_entry_cfg_node)
        # handle loops
        for loop in self.loops:
            # self.loops contain all loops from all functions
            # we only handle loops in current function:
            if loop[0] in this_function_cfg.nodes:
                loop_trip_count_factor = self.handleLoop(loop, this_function_cfg, loop_free_cfg,
                                                         function_entry_cfg_node,
                                                         current_region)
                for block in loop:
                    block_weights[block] *= loop_trip_count_factor

        for block in func.blocks:
            cfg_node = self.cfg.get_node(block.addr)
            weight = block_weights[cfg_node]
            for inst in block.disassembly.insns:
                # how to retrieve the disassembly memonic:
                # print(inst.mnemonic)
                current_region.instructionCount += 1 * weight

            # successors
            for tgt, jmp_kind in self.cfg.get_successors_and_jumpkind(cfg_node):
                # handle call
                if jmp_kind == 'Ijk_Call':
                    tgt_func = self.kb.functions.get_by_addr(tgt.addr)
                    if not tgt_func == func:
                        target_call_region = self.analyze_function(tgt_func)
                        # TODO also use block weight?
                        current_region.include_other(target_call_region)
                    else:
                        # simple recursion
                        # nothing to do, recursion is handled later
                        pass
                pass
        # end for each block

        # handle recursion
        # can detect recursion with self.callgraph_cycles
        for cycle in self.callgraph_cycles:
            if func.addr in cycle:
                self.handleRecursion(current_region)

        self.function_analysis_result_cache[func] = current_region
        return current_region

    def run(self):
        # self.kb has the KnowledgeBase object
        openmp_regions = [func for addr, func in self.kb.functions.items() if '._omp_fn.' in func.name]
        for func in openmp_regions:
            self.result.append(self.analyze_function(func))


angr.analyses.register_analysis(OpenMPRegionAnalysis,
                                'OpenMPRegionAnalysis')  # register the class with angr's global analysis list


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
    def __call__(self, source, outfile, print_cfg=True):
        proj = angr.Project(source, load_options={'auto_load_libs': False})

        if print_cfg:
            cfg = proj.analyses.CFGFast(normalize=True)
            functions = dict(proj.kb.functions)
            for addr, func in functions.items():
                # Edges Style:
                # Edge class 	Color 	Style
                # Conditional True 	Green
                # Conditional False 	Red
                # Unconditional 	Blue
                # Next 	Blue 	Dashed
                # Call 	Black
                # Return 	Gray
                # Fake Return 	Gray 	Dotted
                # Unknown 	Orange
                fname_to_use = outfile + "_" + func.name
                plot_cfg(cfg, fname_to_use, asminst=True, func_addr={func.addr: True}, remove_imports=True,
                         remove_path_terminator=True)

        parallel_regions = proj.analyses.OpenMPRegionAnalysis().result

        with open('%s' % outfile, 'w') as outfile:
            outfile.write(os.path.basename(source) + ': \n')
            outfile.write('\tamount of parallel regions: ' + str(len(parallel_regions)) + '\n')
            if (len(parallel_regions) > 0):
                outfile.write('\tregions: \n')
                writeRegions('\t', parallel_regions, outfile)
            outfile.write('\n')

        return 0
