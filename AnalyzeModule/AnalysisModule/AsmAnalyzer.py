import itertools
import os
import sys
import shutil
import math
import subprocess
from collections import OrderedDict

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


def handleRecursion(region):
    region.recursions += 1


def handleLoop(loop, region):
    # TODO try to get trip count
    region.loops += 1
    region.instructionCount += 399


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

    # calculate weight of each block (probalility of execution ignoring loops)
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

    def analyze_function(self, func):
        if func in self.function_analysis_result_cache:
            return self.function_analysis_result_cache[func]

        # initialize empty new region
        current_region = Region(func.name, func.addr)

        # remove all back edges from cg to find out the branch nesting level of each block
        loop_free_cfg = self.per_function_cfg.copy()
        for block in func.blocks:
            cfg_node = self.cfg.get_node(block.addr)
            # successors
            for tgt, jmp_kind in self.cfg.get_successors_and_jumpkind(cfg_node):
                if tgt.addr < cfg_node.addr:
                    # backward jump
                    try:
                        loop_free_cfg.remove_edge(cfg_node, tgt)
                    except NetworkXError:
                        #  not in graph: nothing to do
                        pass

        block_weights = self.get_block_weight(loop_free_cfg, self.cfg.get_node(func.addr))

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

        # handle loops

        function_entry_cfg_node = self.cfg.get_node(func.addr)
        for loop in self.loops:
            # self.loops contain all loops from all functions
            # we only handle loops in current function:
            if networkx.algorithms.has_path(self.per_function_cfg, function_entry_cfg_node, loop[0]):
                handleLoop(loop, current_region)

        # handle recursion
        # can detect recursion with self.callgraph_cycles
        for cycle in self.callgraph_cycles:
            if func.addr in cycle:
                handleRecursion(current_region)

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
