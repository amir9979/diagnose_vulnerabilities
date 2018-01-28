import networkx as nx
import tempfile
import subprocess
import re

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
    def remove_comment(x):
        if ";" in x:
            if "}" in x:
                return x.split(";")[0] + "}"
            else:
                return x.split(";")[0] + "}"
        else:
            return x
    new_lines = []
    for x in lines:
        if not x.startswith("colorentry")and not x.startswith("//"):# and not x.startswith(" graph {") and not x.startswith("}\n"):
            new_lines.append(x)
    return map(lambda x: x.replace("\n", ""), map(remove_comment, new_lines))

def fixes(graph_string):
        return graph_string.replace("graph:", "graph").replace("node:", "node").replace("edge:", "edge")

def get_graph_elements(lines):
    all_lines = fixes(" ".join(lines))
    ind = all_lines.find("node")
    all_lines = all_lines[ind:]
    return map(lambda elem: elem.strip() + "}", all_lines.split("}"))


def node_to_dict(bunch):
    # input example : { title: "244" label: "__imp____acrt_iob_func" color: 80 bordercolor: black }
    # output example : { title: "244", label: "__imp____acrt_iob_func" ,color: 80 ,bordercolor: black }
    elements = re.sub(r"\f[0-9][0-9]", "", bunch).replace("{","").replace("}","").replace('"',"").replace(":","").lstrip().split(";")[0].split()
    items = zip(elements[::2], elements[1::2])
    return dict(items)


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
        d = node_to_dict(line.replace("node ", ""))
        if "label" in d:
            if "\f" in d["label"]:
                d["label"] = d["label"].replace("\f","")[2:-2]
            # d["signature"] = get_function_signature(d['label'].replace("__ehhandler$", ""))
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

def gdl2gexf(path, out_path=GEXF_GRAPH):
    g = gdl_parse(path)
    # nx.write_gexf(g, out_path)
    return g

def get_dominance(g):
    dominates = nx.algorithms.dominance.immediate_dominators(g, "0")
    if len(g.nodes()) == 1:
        return {}
    dom = {}
    map(lambda tup: dom.setdefault(tup[1], []).append(tup[0]), filter(lambda tup: tup[0] != tup[1], dominates.items()))
    dom.pop("0")
    while len(set(dom.keys()).intersection(set(reduce(list.__add__, dom.values(), [])))) != 0:
        for i in dom:
            for j in dom[i]:
                if j in dom:
                    dom[i].extend(dom[j])
                    dom[j] = []
        dom = dict(filter(lambda tup: tup[1] != [], dom.items()))
    map(lambda i: dom[i].append("0"), dom)
    return dom

def read_map_file(map_path):
    base = int("401000",16)
    to_addr = lambda x: "{0:#0{1}x}".format(int(x,16) + base,8).replace("0x","00")
    with open(map_path) as map_file:
        new_lines = map(lambda x: x.split(), filter(lambda x: ":" in x and x.startswith(" "), map_file.readlines()))
        return dict(map(lambda x: (x[1], to_addr(x[0].split(":")[1])) ,new_lines))

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

def get_labels_addrs(labels, mapping):
    addrs = {}
    for label in labels:
        value = labels[label]
        map_value = value
        if value.startswith("10"):
            map_value = "{0:#0{1}x}".format(int(value,16) - int('10001000',16) + int("400000", 16),8).replace("0x","00")
            # map_value = "{0:#0{1}x}".format(int(value,16) - int('10000000',16) + int("400000", 16),8).replace("0x","00")
        elif value.startswith("00"):
            map_value = value
        else:
            if "@" in value:
                func_name = value.split("@")[0]#.replace("_", "")
                map_value = mapping[filter(lambda x: func_name in x or func_name.replace("_", ""), mapping)[0]]
            elif value in mapping:
                map_value = mapping[value]
            elif "_" in value:
                map_value = value.split("_")[1]
            else:
                raise RuntimeError("no mapping for value %s" % value)
        print label, labels[label]
        addrs[label] = hex(int(map_value, 16) - int("400000", 16))
    return addrs

if __name__ == "__main__":
    g = gdl2gexf(r"C:\Temp\f8fd4w\iwcmd_main.gdl", r"C:\Temp\graphs\g.gexf")
    mapping = read_map_file(r"C:\Temp\f8fd4w\map.map")
    dom = get_dominance(g)
    labels = nx.get_node_attributes(g, "label")
    nodes_addrs = get_labels_addrs(labels, mapping)
    print dom
    print nodes_addrs
    dom_addrs = map(lambda key: (nodes_addrs[key], "", " ".join(map(lambda val: nodes_addrs[val], dom[key]))), dom)
    dom_addrs = map(lambda key: (nodes_addrs[key], "",
                                 " ".join(
                                     map(lambda val: nodes_addrs[val], dom[key]))), dom)
    from os import listdir
    from os.path import isfile, join
    onlyfiles = [join(r"C:\Temp\graphs", f) for f in listdir(r"C:\Temp\graphs") if isfile(join(r"C:\Temp\graphs", f)) and f.endswith("gdl")]
    for f in onlyfiles:
        print f
        # g = gdl2gexf(r"C:\Temp\graphs\iwcmd_main.gdl", r"C:\Temp\graphs\g.gexf")
        g = gdl2gexf(f, r"C:\Temp\graphs\g.gexf")
        dom = get_dominance(g)
        labels = nx.get_node_attributes(g, "label")
        nodes_addrs = get_labels_addrs(labels, mapping)
        nodes_addrs = nodes_addrs
    exit()
    g = nx.read_gexf(GEXF_GRAPH)
    print "nodes: " , len(g.nodes())
    print_all_names(g)
    g = remove_library_function_nodes(g)
    print "nodes: ", len(g.nodes())
    reduced_graph = reduce_graph(g)
    print "nodes: ", len(reduced_graph.nodes())
    nx.write_gexf(reduced_graph, REDUCED_GRAPH)
    print_all_names(g)

    exit()
    optional_inline = []
    for n in g.nodes():
        if len(g.in_edges([n])) == 1:
            optional_inline.append(n)
    x =0


