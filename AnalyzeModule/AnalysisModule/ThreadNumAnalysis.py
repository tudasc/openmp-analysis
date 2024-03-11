import re

import networkx as nx


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


result_cache={}
# returns set of addresses of each instruction in the function that we know to be based on thread_num
def get_instructions_based_on_thread_num(project,full_cfg, this_function_loop_free_cfg,cache_key=None):
    if cache_key is not None and cache_key in result_cache:
        return result_cache[cache_key]

    assert len(list(nx.simple_cycles(this_function_loop_free_cfg))) == 0  # no cycles
    return_register = 'eax'  # may be architecture specific
    try:
        thread_num_func = project.kb.functions['omp_get_thread_num']
    except KeyError:
        return set()  # empty

    result = set()

    to_visit = dict()
    to_add = dict()  # BFS
    visited = set()
    # find calls to omp_get_thread_num
    for bb_addr in this_function_loop_free_cfg:
        for tgt, jmp_kind in full_cfg.get_successors_and_jumpkind(bb_addr):
            if jmp_kind == 'Ijk_Call':
                tgt_func = project.kb.functions.get_by_addr(tgt.addr)
                if tgt_func == thread_num_func:
                    bb = project.factory.block(bb_addr.addr)
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
        bb = project.factory.block(bb_addr.addr)
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
                    elif inst.mnemonic in ["cwd","cdq","cqo"]:
                        if 'edx' in tainted_registers:
                            # overwritten
                            remove_tainted_register(tainted_registers, 'edx')
                    elif inst.mnemonic in ["cbw","cwde","cdqe"]:
                        # nothing to do: byte to word keeps the current "taint status" if a part of eax is tainted, all of it is tainted
                        pass
                    elif inst.mnemonic in ["nop","endbr64"]:
                        # nothing to do, these instructions don't do something harmful to the registers
                        pass
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

    if cache_key is not None:
        result_cache[cache_key] = result
    return result
