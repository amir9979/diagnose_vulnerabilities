import networkx as nx
import tempfile
import subprocess

path = r"C:\Temp\all.gdl"
GEXF_GRAPH = "c:\\temp\\graphFull.gexf"
REDUCED_GRAPH = "c:\\temp\\graphReduced.gexf"


def get_function_signature(name):
    run_commands = [r"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\undname.exe"]
    proc = subprocess.Popen(run_commands + [name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=True)
    (out, err) = proc.communicate()
    return out.split("is :-")[1].replace("\n", "").replace('"', '')


def filter_lines(lines):
    # filter comments that starts with //
    # filter colorentry lines
    new_lines = []
    for x in lines:
        if not x.startswith("colorentry")and  not x.startswith("//") and not x.startswith("graph {") and not x.startswith("}\n"):
            new_lines.append(x)
    return new_lines

def fixes(graph_string):
        return graph_string.replace("graph:", "graph").replace("node:", "node").replace("edge:", "edge")

def get_graph_elements(lines):
    all_lines = fixes("\n".join(lines))
    elements = []
    search_index = 0
    for prefix in ["node {", "edge {"]:
        while(search_index < len(all_lines)):
            start_elemet = all_lines.find(prefix, search_index)
            if start_elemet == -1:
                break
            end_element = all_lines.find("}", start_elemet)
            if end_element == -1:
                raise Exception("no } on end")
            elements.append(all_lines[start_elemet:end_element].replace("\n", ";"))
            search_index = end_element
    return elements

def bunch_to_dict(bunch):
    # input example : { title: "244" label: "__imp____acrt_iob_func" color: 80 bordercolor: black }
    # output example : { title: "244", label: "__imp____acrt_iob_func" ,color: 80 ,bordercolor: black }
    elements = bunch.replace("{","").replace("}","").replace('"',"").replace(":","").lstrip().split()
    items = zip(elements[::2], elements[1::2])
    return dict(items)


def gdl_parse(path):
    g = nx.DiGraph()
    lines = open(path).readlines()
    nodes = []
    edges = []
    def parse_node(line):
        d = bunch_to_dict(line.replace("node ", ""))
        d["signature"] = get_function_signature(d['label'].replace("__ehhandler$", ""))
        nodes.append((d['title'], d))

    def parse_edge(line):
        d = bunch_to_dict(line.replace("edge ", ""))
        edges.append((d['sourcename'], d['targetname']))

    filtered = filter_lines(lines)
    for line in get_graph_elements(filtered):
        if line.startswith("node"):
            parse_node(line)
        if line.startswith("edge"):
            parse_edge(line)
    g.add_nodes_from(nodes)
    g.add_edges_from(edges)
    return g

def gdl2gexf(path):
    g = gdl_parse(path)
    nx.write_gexf(g, GEXF_GRAPH)

def inline_functions(g):
    inlined_graph = g.to_directed()
    for n in inlined_graph.nodes():
        if len(inlined_graph.in_edges([n])) == 1:
            parent = inlined_graph.predecessors(n)[0]
            additional_edges = []
            for successor in inlined_graph.neighbors(n):
                additional_edges.append((parent, successor))
            inlined_graph.remove_node(n)
            inlined_graph.add_edges_from(additional_edges)
    return inlined_graph


def is_inline_possible(g):
    count = 0
    for n in g.nodes():
        if len(g.in_edges([n])) == 1:
            count += 1
    return count

def remove_self_loops(g):
    g.remove_edges_from(g.selfloop_edges())
    return g

def get_roots(g):
    roots = []
    for node in g.nodes():
        if len(g.in_edges([node])) == 1:
            roots.append(node)
    return roots

def simple_clustring(g):
    colored_nodes = {}
    for node in g.nodes():
        colored_nodes[node] = []
    roots = get_roots(g)
    for root in roots:
        colored_nodes[root] = [root]

def remove_unconnected_nodes(g):
    for node in g.nodes():
        if len(g.edges([node])) == 0:
            g.remove_node(node)
    return g

def remove_library_function_nodes(g):
    libs = ["std::"]
    for node in g.nodes():
        for lib in libs:
            if lib in g.node[node]["signature"]:
                g.remove_node(node)
                break
    return g


def remove_crt_function_nodes(g):
    libs = ["__scrt", "__vcrt", "__crt", "__acrt"]
    for node in g.nodes():
        for lib in libs:
            if lib.lower() in g.node[node]["signature"]:
                g.remove_node(node)
                break
    return g

def get_namespaces(g):
    namespaces = []
    for node in g.nodes():
        g.node[node]["signature"].split()

def print_all_names(g):
    for node in g.nodes():
        print g.node[node]["signature"]

def connected_components(g):
    connected = list(nx.weakly_connected_components(g))
    connected_names = []
    for components in connected:
        names = []
        for node in components:
            names.append(g.node[node]["signature"])
        connected_names.append(names)
    return connected_names

def reduce_graph(g):
    reduced_graph = g.to_directed()
    while is_inline_possible(reduced_graph) > 0:
        reduced_graph = remove_self_loops(inline_functions(reduced_graph))
    return reduced_graph

if __name__ == "__main__":
    # gdl2gexf(path)
    # exit()
    g = nx.read_gexf(GEXF_GRAPH)
    print "nodes: " , len(g.nodes())
    # print_all_names(g)
    g = remove_library_function_nodes(g)
    print "nodes: ", len(g.nodes())
    # reduced_graph = reduce_graph(g)
    # print "nodes: ", len(reduced_graph.nodes())
    # nx.write_gexf(reduced_graph, REDUCED_GRAPH)
    print_all_names(g)

    exit()
    optional_inline = []
    for n in g.nodes():
        if len(g.in_edges([n])) == 1:
            optional_inline.append(n)
    x =0


