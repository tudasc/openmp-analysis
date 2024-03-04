import re

import angr
import networkx
import networkx as nx
import pandas as pd
from angrutils import plot_cfg

from AnalyzeModule.AnalysisModule.CFGAnalysis import get_loop_guard, get_block_weight, remove_back_edges

hex_pattern = re.compile("0[xX][0-9a-fA-F]+")

col_names = ["name", "addr", "instructions_flat", "instructions_weighted", "default_tripcount_loops",
             "known_tripcount_loops", "thread_dependant_trip_count_loops", "recursions"]

DEFAULT_TRIP_COUNT_GUESS = 3


def get_region(name, start_addr):
    return pd.Series(data=[name, start_addr] + [0 for i in range(len(col_names) - 2)], index=col_names)


def combine_region(region_a, region_b, weight=1):
    cols_to_combine = [c for c in col_names if c not in ["name", "addr", "instructions_weighted"]]
    region_a[cols_to_combine] += region_b[cols_to_combine]
    region_a["instructions_weighted"] += region_b["instructions_weighted"] * weight
    return region_a


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
                   'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                   'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
                   'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']


# if one reg is only a lower part of another
register_equivalent = [['rax', 'eax', 'ax'], ['rbx', 'ebx', 'bx'], ['rcx', 'ecx', 'cx'], ['rdx', 'edx', 'dx'],
                       ['rsp', 'esp', 'sp'], ['rsb', 'esb', 'sb'], ['rdi', 'edi', 'di'], ['rsi', 'esi', 'si'],
                       ['r8', 'r8d', 'r8w'], ['r9', 'r9d', 'r9w'], ['r10', 'r10d', 'r10w'], ['r11', 'r11d', 'r11w'],
                       ['r12', 'r12d', 'r12w'], ['r13', 'r13d', 'r13w'], ['r14', 'r14d', 'r14w'],
                       ['r15', 'r15d', 'r15w']]


def add_tainted_register(set, reg):
    assert is_register(reg)
    set.add(reg)
    for eq in register_equivalent:
        if reg in eq:
            for rr in eq:
                set.add(rr)


def remove_tainted_register(set, reg):
    if reg in set:
        set.remove(reg)

    for eq in register_equivalent:
        if reg in eq:
            for rr in eq:
                if rr in set:
                    set.remove(rr)


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
        self.result = pd.DataFrame(columns=col_names)
        self.run()

    def handleRecursion(self, region):
        region['recursions'] += 1

    # returns set of addresses of each instruction in the function that we know to be based on thread_num
    def get_instructions_based_on_thread_num(self, this_function_loop_free_cfg):
        assert len(list(nx.simple_cycles(this_function_loop_free_cfg))) == 0  # no cycles
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
                        # print(terminator)
                        result.add(terminator.address)
                        # move from there
                        tainted_registers = set()
                        add_tainted_register(tainted_registers, return_register)
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
                if not (len(to_visit) == 0 and len(to_add) == 0):  # avoid endless recursion
                    # TODO there may exist other possibilities of endless recursion
                    # to be visitied later
                    if bb_addr in to_add:
                        to_add[bb_addr] = tainted_registers.intersection(to_add[bb_addr])
                    else:
                        to_add[bb_addr] = tainted_registers.copy()
                    continue
            bb = self.project.factory.block(bb_addr.addr)
            for inst in bb.disassembly.insns:
                operands = inst.op_str.split(',')
                operands = [o.strip() for o in operands]
                if len(operands) == 2:
                    if inst.mnemonic == "mov":
                        if is_register(operands[0]) and is_register(operands[1]):
                            if operands[1] in tainted_registers:
                                result.add(inst.address)
                                add_tainted_register(tainted_registers, operands[0])
                            else:
                                # is overridden
                                remove_tainted_register(tainted_registers, operands[0])
                        else:
                            # may be overridden
                            # will also work if it is not a register or not in set at all
                            remove_tainted_register(tainted_registers, operands[0])
                    elif inst.mnemonic in ['add', 'imul']:
                        # the result value is not "overwritten" in the sense, that the result does depend on input
                        # print(inst)
                        if operands[0] in tainted_registers:
                            result.add(inst.address)
                        if operands[1] in tainted_registers:
                            result.add(inst.address)
                            add_tainted_register(tainted_registers, operands[0])
                    elif inst.mnemonic == "lea":
                        # if it follows a specific format: [rax + rcx] - 2 registers added
                        pattern = re.compile(r"^\[[a-z]{3} \+ [a-z]{3}\]$")
                        if pattern.match(operands[1]):
                            # the two registers used:
                            r1 = operands[1][1:4]
                            r2 = operands[1][7:10]
                            if r1 in tainted_registers or r2 in tainted_registers:
                                # depends on tainted value
                                result.add(inst.address)
                                add_tainted_register(tainted_registers, operands[0])
                            else:
                                remove_tainted_register(tainted_registers, operands[0])
                        else:
                            remove_tainted_register(tainted_registers, operands[0])
                    elif inst.mnemonic in ['cmp']:
                        # readonly
                        if operands[0] in tainted_registers or operands[1] in tainted_registers:
                            result.add(inst.address)
                    else:
                        # register overwritten
                        # this is the conservative method anything written into this register marks it as not dependent on thread num anymore
                        # there may be more possiblitiies of instruction that dont break taintedness
                        remove_tainted_register(tainted_registers, operands[0])
                        # even more conservative:
                        remove_tainted_register(tainted_registers, operands[1])


                elif len(operands) == 1:
                    if operands[0] == "":
                        # 0 operands
                        if inst.mnemonic == "ret":
                            continue  # end of this branch
                        elif inst.mnemonic == "cdq":
                            if 'edx' in tainted_registers:
                                # overwritten
                                remove_tainted_register(tainted_registers, 'edx')
                        else:
                            print(inst)
                            assert False and "operation not supported"
                    else:
                        if inst.mnemonic == 'call':
                            if return_register in tainted_registers:
                                remove_tainted_register(tainted_registers, return_register)
                        elif inst.mnemonic in ['div', 'idiv']:
                            if 'eax' in tainted_registers or operands[0] in tainted_registers:
                                result.add(inst.address)
                                add_tainted_register(tainted_registers, "eax")
                                add_tainted_register(tainted_registers, "edx")
                            else:
                                remove_tainted_register(tainted_registers, "eax")
                                remove_tainted_register(tainted_registers, "edx")
                        elif operands[0] in tainted_registers:
                            remove_tainted_register(tainted_registers, operands[0])
                            # remove, as it may be written (e.g. pop)

            # end for insts
            visited.add(bb_addr)

            for succ in this_function_loop_free_cfg.successors(bb_addr):
                if succ in to_visit:
                    to_visit[succ] = tainted_registers.intersection(to_visit[succ])
                elif succ in to_add:
                    to_add[succ] = tainted_registers.intersection(to_add[succ])
                else:
                    if len(tainted_registers) > 0:  # abort early if nothing more to do
                        to_add[succ] = tainted_registers.copy()

        return result

    def handleLoop(self, loop, this_function_cfg, this_function_loop_free_cfg, entry_node, region):
        # try to get trip count of loop

        trip_count_guess = self.get_tripcount_guess(entry_node, loop, this_function_cfg, this_function_loop_free_cfg)

        if trip_count_guess == 'DEFAULT':
            region['default_tripcount_loops'] += 1
            trip_count_guess = DEFAULT_TRIP_COUNT_GUESS
        elif trip_count_guess == 'DEPEND_ON_THREAD_NUM':
            trip_count_guess = 1
            region['thread_dependant_trip_count_loops'] += 1
        else:
            region['known_tripcount_loops'] += 1
        return trip_count_guess

    def get_tripcount_guess(self, entry_node, loop, this_function_cfg, this_function_loop_free_cfg):
        trip_count_guess = 'DEFAULT'
        guard_block_addr = get_loop_guard(loop, this_function_cfg, entry_node)
        if guard_block_addr is not None:
            guard_block = self.project.factory.block(guard_block_addr.addr)
            if guard_block.instructions >= 2:  # has another instruction
                if guard_block.disassembly.insns[-2].mnemonic == "cmp":
                    cmp = guard_block.disassembly.insns[-2]
                    # found the loops cmp instruction
                    # check if it has a constant value
                    operand_1 = cmp.op_str.split(',')[0].strip()
                    operand_2 = cmp.op_str.split(',')[1].strip()
                    as_int = None
                    try:
                        as_int = int(operand_2)  # decimal constant
                    except ValueError:
                        pass
                    if hex_pattern.match(operand_2):  # is hexnum
                        as_int = int(operand_2[2:], 16)
                    if as_int is not None:
                        # print("Found Constant Trip count of loop: %d" % int(as_int))
                        # check if other opreand is incremented by 1 every loop trip
                        for bb_addr in loop:
                            bb = self.project.factory.block(bb_addr.addr)
                            for inst in bb.disassembly.insns:
                                if inst.mnemonic == 'add':
                                    if inst.op_str.split(',')[0].strip() == operand_1:
                                        if inst.op_str.split(',')[1].strip() == '1':
                                            # found increment by 1
                                            trip_count_guess = int(as_int)
                                            break
                    # end if as_int not None

                    # check if val is known to be based of num_threads
                    # TODO optimization: dont calculate this set several times for multiple loops inside a function
                    if cmp.address in self.get_instructions_based_on_thread_num(this_function_loop_free_cfg):
                        assert trip_count_guess == 'DEFAULT'
                        # print("Found Trip count dependant on NUM_THREADS")
                        trip_count_guess = 'DEPEND_ON_THREAD_NUM'
                    # pass
        return trip_count_guess

    def analyze_function(self, func):
        if func in self.function_analysis_result_cache:
            return self.function_analysis_result_cache[func]

        # initialize empty new region
        current_region = get_region(func.name, func.addr)

        function_entry_cfg_node = self.cfg.get_node(func.addr)
        this_function_cfg = networkx.subgraph(self.per_function_cfg,
                                              {function_entry_cfg_node} | networkx.descendants(self.per_function_cfg,
                                                                                               function_entry_cfg_node))
        # remove all back edges from cfg to approximate out the branch nesting level of each block
        loop_free_cfg = remove_back_edges(this_function_cfg, function_entry_cfg_node)
        # end for each block

        # instruction weight of each block
        block_weights = get_block_weight(loop_free_cfg, function_entry_cfg_node)
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
                current_region["instructions_weighted"] += 1 * weight
                current_region["instructions_flat"] += 1 * weight

            # successors
            for tgt, jmp_kind in self.cfg.get_successors_and_jumpkind(cfg_node):
                # handle call
                if jmp_kind == 'Ijk_Call':
                    tgt_func = self.kb.functions.get_by_addr(tgt.addr)
                    if not tgt_func == func:
                        target_call_region = self.analyze_function(tgt_func)
                        # TODO use block weight?
                        combine_region(current_region, target_call_region)
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
            self.result.loc[0] = self.analyze_function(func)  # append


angr.analyses.register_analysis(OpenMPRegionAnalysis,
                                'OpenMPRegionAnalysis')  # register the class with angr's global analysis list


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
        assert isinstance(parallel_regions, pd.DataFrame)

        parallel_regions.to_csv(outfile)

        return 0
