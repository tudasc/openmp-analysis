import networkx
import networkx as nx

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
    prev_node = v
    cur_node = im_dominators[v]
    while prev_node != cur_node:
        if cur_node == u:
            return True  # found u in domtree
        # go one lvl up in the domtree
        prev_node = cur_node
        cur_node = im_dominators[prev_node]

    return False


def get_loop_guard(loop, this_function_cfg, entry_node):
    # the loop guard block dominates all loop blocks
    im_dominators = networkx.immediate_dominators(this_function_cfg, entry_node)

    guards = []
    for candidate in loop:
        is_entry = True
        is_exit = True

        for bbb in loop:
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
            if succ not in loop:
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
# iterative algorithm: remove the edge that is included in most loops, but only if all nodes are still reachable, until no more loops remain
def remove_back_edges(this_function_cfg, entry_node):
    result = this_function_cfg.copy()
    reachable = {entry_node} | networkx.descendants(result,
                                                    entry_node)
    assert reachable == set(result.nodes)

    loops = list(networkx.simple_cycles(result))
    num_loops = len(loops)
    while len(loops) > 0:
        removal_candidates = {}
        # collect removal candidates
        for loop in loops:
            for i in range(len(loop) - 1):
                if (loop[i], loop[i + 1]) not in removal_candidates:
                    removal_candidates[(loop[i], loop[i + 1])] = 0
                removal_candidates[(loop[i], loop[i + 1])] += 1
            # wrap-around
            if (loop[-1], loop[0]) not in removal_candidates:
                removal_candidates[(loop[-1], loop[0])] = 0
            removal_candidates[(loop[-1], loop[0])] += 1
        # sort by number of cycles the edge is part of
        removal_candidates = dict(sorted(removal_candidates.items(), key=lambda item: item[1]))
        # try removal
        for edge, _ in removal_candidates.items():
            result.remove_edge(edge[0], edge[1])
            reachable = {entry_node} | networkx.descendants(result,
                                                            entry_node)
            if not reachable == set(result.nodes):
                # removal partitioned graph
                result.add_edge(edge[0], edge[1])
            else:
                # found edge to remove
                break
        # check for other loops
        loops = list(networkx.simple_cycles(result))
        assert len(loops) < num_loops
        num_loops = len(loops)

    reachable = {entry_node} | networkx.descendants(result, entry_node)
    assert reachable == set(result.nodes)
    assert len(list(networkx.simple_cycles(result))) == 0
    return result
