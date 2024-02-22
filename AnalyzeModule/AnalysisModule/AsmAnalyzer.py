import itertools
import os
import sys
import shutil
import math
import subprocess
from collections import OrderedDict
import matplotlib.pyplot as plt

import angr
import networkx
import networkx as nx
from angrutils import plot_cfg
from networkx import NetworkXError

# from angrutils import *

from AnalyzeModule.AnalysisModule.Region import Region

# from AnalysisModule.Region import Region

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

    def get_loop_guard(self, loop, entry_node):
        # the loop guard block dominates all loop blocks
        print(entry_node)
        print(self.per_function_cfg)
        im_dominators = networkx.immediate_dominators(self.per_function_cfg, entry_node)

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

    def handleLoop(self, loop, entry_node, region):
        # try to get trip count of loop

        trip_count_guess = 'DEFAULT'
        back_jumps = []

        guard_block = self.get_loop_guard(loop, entry_node)

        if guard_block is not None:
            if guard_block.instructions >= 2:  # has another instruction
                if guard_block.disassembly.insns[-2].mnemonic == "cmp":
                    cmp = guard_block.disassembly.insns[-2]
                    print(cmp)
                    print(cmp.op_str)
                    print(type(cmp))
                    # TODO found the loops cmp instruction
                    # TODO check if it has a constant value
                    # TODO check if val is known to be based of num_threads
                    # pass

        region.loops += 1

        if trip_count_guess == 'DEFAULT':
            trip_count_guess = 3  # TODO should be a global parameter
        return trip_count_guess

    # calculate weight of each block (probability of execution ignoring loops)
    # with each branch having equal probability
    def get_block_weight(self, loop_free_cfg, entry_node):
        # only the graph of the given function
        this_function_cfg = networkx.subgraph(loop_free_cfg,
                                              {entry_node} | networkx.descendants(loop_free_cfg, entry_node))

        assert len(list(nx.simple_cycles(this_function_cfg))) == 0  # no cycles
        result = {node: 0.0 for node in this_function_cfg.nodes}
        result[entry_node] = 1.0

        to_visit = {entry_node}
        to_add = set()  # to implement BFS
        visited = set()

        while len(to_visit) > 0:
            node = to_visit.pop()
            for pred in this_function_cfg.predecessors(node):
                if pred not in visited:
                    # not all incoming edges where visited
                    to_add.add(node)  # avoid endless recursion
                    continue
            visited.add(node)
            num_successors = len(this_function_cfg.succ[node])
            for succ in this_function_cfg.succ[node]:
                to_add.add(succ)
                # propagate probalility
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
        # remove all back edges from cfg to APPROXIMATE out the branch nesting level of each block
        loop_free_cfg = self.remove_back_edges(this_function_cfg, function_entry_cfg_node)
        # end for each block
        this_function_cfg = networkx.subgraph(self.per_function_cfg,
                                              {function_entry_cfg_node} | networkx.descendants(self.per_function_cfg,
                                                                                               function_entry_cfg_node))
        # instruction weight of each block
        block_weights = self.get_block_weight(loop_free_cfg, function_entry_cfg_node)
        print(block_weights)
        # handle loops
        for loop in self.loops:
            # self.loops contain all loops from all functions
            # we only handle loops in current function:
            if networkx.algorithms.has_path(self.per_function_cfg, function_entry_cfg_node, loop[0]):
                loop_trip_count_factor = self.handleLoop(loop, function_entry_cfg_node, current_region)
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
                # TODO handle if
                # handle call
                if jmp_kind == 'Ijk_Call':
                    tgt_func = self.kb.functions.get_by_addr(tgt.addr)
                    if not tgt_func == func:
                        target_call_region = self.analyze_function(tgt_func)
                        # TODO also use block weight
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
