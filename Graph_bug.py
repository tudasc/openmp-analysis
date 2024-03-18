import networkx
import networkx as nx
from matplotlib import pyplot as plt


def main():
    g = nx.read_adjlist("test_graph.adjlist", create_using=nx.DiGraph)
    print("try finding cycle in O( %i + %i)" % (len(g.nodes), len(g.edges)))

    nx.draw(g)
    plt.show()

    # the entry_node is the node from which we can reach all others
    entry_node = None
    for node in g.nodes:
        reachable = {node} | networkx.descendants(g, node)
        if reachable == set(g.nodes):
            assert entry_node is None  # only one entry node
            entry_node = node
            #break

    assert entry_node is not None


    try:
        cycle = nx.find_cycle(g, source=entry_node, orientation='original')
        print("Found cycle with length")
        print(len(cycle))
    except nx.NetworkXNoCycle:
        print("No cycles")



if __name__ == "__main__":
    main()
