import copy
import gc

import networkx
import networkx as nx
from matplotlib import pyplot as plt


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


def dominates(u, v, im_dominators):
    # im_dominators holds the parent in the domtree
    prev_node = v
    cur_node = im_dominators[v]
    while prev_node != cur_node:  # not reached the top
        if cur_node == u:
            return True  # found u in domtree
        # go one lvl up in the domtree
        prev_node = cur_node
        cur_node = im_dominators[prev_node]

    return False


def get_loop_nodes(back_edge, this_function_loop_free_cfg):
    return [n for n in this_function_loop_free_cfg.nodes if
            # back-edge has "reverse" direction
            nx.has_path(this_function_loop_free_cfg, back_edge[1], n)
            and nx.has_path(this_function_loop_free_cfg, n, back_edge[0])]


def get_loop_guard(back_edge, this_function_cfg, this_function_loop_free_cfg, entry_node):
    # the loop guard block dominates all loop blocks
    im_dominators = networkx.immediate_dominators(this_function_cfg, entry_node)
    assert im_dominators[entry_node] == entry_node

    loop_nodes = get_loop_nodes(back_edge, this_function_loop_free_cfg)

    guards = []
    for candidate in loop_nodes:
        is_entry = True
        is_exit = True

        for bbb in loop_nodes:
            if dominates(candidate, bbb, im_dominators):
                is_entry = False
            if dominates(bbb, candidate, im_dominators):
                is_exit = False
        if is_entry or is_exit:
            guards.append(candidate)

    leave_loop = []
    for guard in guards:
        goes_outside = False
        for succ in this_function_cfg.successors(guard):
            if succ not in loop_nodes:
                goes_outside = True
                break
        if goes_outside:
            leave_loop.append(guard)

    if len(leave_loop) == 1:
        return leave_loop[0]

    # not found
    return None


# calculate weight of each block (probability of execution ignoring loops)
# with each branch having equal probability
def get_block_weight(loop_free_cfg, entry_node):
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
# iterative algorithm: remove the last enge in a cycle detected by DFS, until no more loops remain. checks that all nodes are still reachable
def remove_back_edges(this_function_cfg, entry_node):
    result = this_function_cfg.copy()
    back_edges = []

    reachable = {entry_node} | networkx.descendants(result, entry_node)
    assert reachable == set(result.nodes)

    while True:
        # return when no cycle exception is raised
        try:
            cycle = nx.find_cycle(result, source=entry_node, orientation='original')
        except nx.NetworkXNoCycle:
            reachable = {entry_node} | networkx.descendants(result, entry_node)
            assert reachable == set(result.nodes)
            return result, back_edges

        removal_candidate = cycle[-1]
        result.remove_edge(removal_candidate[0], removal_candidate[1])
        back_edges.append(removal_candidate)

        reachable = {entry_node} | networkx.descendants(result, entry_node)
        assert reachable == set(result.nodes)  # removal should not partition graph
