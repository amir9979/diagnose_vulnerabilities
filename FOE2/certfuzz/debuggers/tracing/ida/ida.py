__author__ = 'amir'
import ida_consts
import os
import subprocess
import tempfile
import gdl2nx
import pefile
import networkx as nx
from itertools import product

already_imported_modules = []


def init_tmp_dir(binary_file):
    path = binary_file.replace("C:\\", "").replace("\\", "_").replace(".exe", "").replace(".dll", "")
    ida_consts.TMPS_DIR = os.path.join(r"C:\temp\windbg_functions", str(abs(hash(path))))
    if not  os.path.exists(ida_consts.TMPS_DIR):
        os.mkdir(ida_consts.TMPS_DIR)


def make_tmp_file(prefix):
    return tempfile.mktemp(prefix=prefix, dir=ida_consts.TMPS_DIR)


def getImportedModules(pe_file_to_analyze):
    global already_imported_modules
    already_imported_modules.append(pe_file_to_analyze)
    if not os.path.exists(pe_file_to_analyze):
        return []
    pe = pefile.PE(pe_file_to_analyze)
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        path = os.path.join(os.path.dirname(pe_file_to_analyze), entry.dll)
        if os.path.exists(path) and path not in already_imported_modules:
            getImportedModules(path)
    return already_imported_modules


def get_entry_points_addresses(pe_file_to_analyze):
    pe = pefile.PE(pe_file_to_analyze)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return map(lambda entry: "{0}={1}".format(hex(entry.address) , entry.name), pe.DIRECTORY_ENTRY_EXPORT.symbols)
    return ["0x{0}={1}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint, "entry_point")]


def extract_functions_list(ida_out):
    """
    extract functions list from script output
    :return: list of functions to break on
    """
    return map(lambda x: x.replace("\n", "").split("="), set(ida_out))


def get_command_on_breakpoint(address, function_name, image_name, granularity = ida_consts.DLL_GRANULARITY):
    """
    :param address: address to break in
    :param granularity: dll, function or xref
    :return: command to run on this breakpoint
    """
    command = []
    command.append(".echo {0}".format(ida_consts.BEGIN_BREAKPOINT_BLOCK))
    if granularity == ida_consts.DLL_GRANULARITY:
        command.append("lmf")
    if granularity != ida_consts.DLL_GRANULARITY:
        command.append(".echo {0}&{1}#{2}".format(address,function_name,image_name))
    command.append(".echo {0}".format(ida_consts.END_BREAKPOINT_BLOCK))
    command.append('g')
    return ";".join(command)


def generate_breakpoints_list(addrs, image_name, granularity):
    """
    generate list of breakpoints to windbg
    :param addrs: list of addresses
    :return: str of one time trace breakpoints
    """
    command = '.foreach (addr {.fnent ADDRESS} ) { .if ($spat("${addr}", "*No function entry for*" ) == 1) {} .else { bu /1 ADDRESS "COMMAND"}}'
    command = ' bu /1 ADDRESS "COMMAND"'
    return map(lambda addr:command.replace("ADDRESS", "{0} + {1}".format(image_name, addr[0])).replace("COMMAND",
                                                            get_command_on_breakpoint(addr[0] if len(addr) == 2 else addr[2], addr[1], image_name, granularity)), addrs)

def create_breakpoint_list_for_modules(modules):
    return map(lambda module: r'bm /1 {0}!* ".echo {1};k 1; .echo {2};g"'.format(os.path.basename(module).split(".")[0],
                                                                                 ida_consts.BEGIN_BREAKPOINT_BLOCK,
                                                                                 ida_consts.END_BREAKPOINT_BLOCK), modules)


def get_ida_script_and_params(granularity, ida_out_file, module_name, tracing_data):
    if granularity == ida_consts.DOMINATOR_GRANULARITY:
        map_file = os.path.join(ida_consts.DOMINATOR_TMP_DIR, "map.map")
        return " ".join([ida_consts.IDA_GRAPHS_SCRIPT, map_file, ida_consts.DOMINATOR_TMP_DIR])
    if granularity in [ida_consts.CHUNK_GRANULARITY, ida_consts.XREF_GRANULARITY] and \
                    tracing_data != None and module_name in tracing_data:
        functions_file = tempfile.mktemp()
        with open(functions_file, "wb") as f:
            f.writelines("\n".join(tracing_data[module_name]))
        script = ida_consts.IDA_CHUNKS_SCRIPT if granularity == ida_consts.CHUNK_GRANULARITY else ida_consts.IDA_XREFS_SCRIPT
        return "{0} {1} {2} {3}".format(script, functions_file, ida_out_file,
                                        module_name.split(".")[1])
    else:
        return "{0} {1} {2}".format(ida_consts.IDA_SCRIPT, ida_out_file, module_name.split(".")[1])


def create_call_graphs(binary_path, map_file_path, graphs_dir):
    db_file = make_tmp_file(r"db_file_")
    command = r'"{0}" -T"Portable executable for 80386" -R -o"{1}" -S"{2} {3} {4}" "{5}"'.\
        format(ida_consts.IDA_EXE, db_file, ida_consts.IDA_GRAPHS_SCRIPT, map_file_path, graphs_dir, binary_path)
    print command
    p = subprocess.Popen(command, stdout=open(os.devnull), stderr=open(os.devnull),
                         cwd=ida_consts.PWD, universal_newlines=True)
    p.communicate()

def dominator_breakpoints(tracing_data):
    dominating = {}
    for image in tracing_data:
        temp_dir = tempfile.mkdtemp(prefix="c:\\temp\\")
        map_file = os.path.join(temp_dir, "map.map")
        create_call_graphs(image, map_file, temp_dir)
        gdl_files = filter(lambda f: f.endswith("gdl"), map(lambda f:  os.path.join(temp_dir, f), os.listdir(temp_dir)))
        mapping = gdl2nx.read_map_file(map_file)
        for f in gdl_files:
            func_name = os.path.basename(f).split(".")[0]
            if not mapping[func_name] in tracing_data[image]:
                continue
            print func_name
            g = gdl2nx.gdl2gexf(f)
            dom = gdl2nx.get_dominance(g)
            labels = nx.get_node_attributes(g, "label")
            nodes_addrs = gdl2nx.get_labels_addrs(labels, mapping)
            dom_addrs = map(lambda key: (nodes_addrs[key], func_name,
                                         ida_consts.DOMINATOR_SEP.join(map(lambda val: nodes_addrs[val], dom[key]))), dom)
            dominating.setdefault(image, []).append(dom_addrs)
    return dominating


def get_bp_traces(binary_file, break_on_dlls, granularity, tracing_data):
    """
    run radare to extract breakpoints to functions
    :param binary_file: path to binary file to use
    :return: list of traces
    """
    funcs = {}

    modules = []
    if break_on_dlls:
        modules = getImportedModules(binary_file)
    else:
        modules = [binary_file]
    # return create_breakpoint_list_for_modules(modules)
    breakpoints = []

    for module in modules:
        image_name = os.path.basename(module)
        if granularity == ida_consts.XREF_GRANULARITY:
            for key in tracing_data:
                func, dll = key.split("#")
                if dll == image_name.split(".")[0]:
                    funcs.setdefault(image_name, []).extend(list(product(tracing_data[key], [func])))
            continue
        ida_out_file = make_tmp_file(r"out_file_" + image_name.replace(".dll", "") + "_")
        ida_call_script = get_ida_script_and_params(granularity, ida_out_file, image_name, tracing_data)
        db_file = make_tmp_file(r"db_file_")
        command = r'"{0}" -T"Portable executable for 80386" -R -o"{1}" -S"{2}" "{3}"'.format(ida_consts.IDA_EXE, db_file, ida_call_script, module)
        print command
        p = subprocess.Popen(command, stdout=open(os.devnull), stderr=open(os.devnull),
                             cwd=ida_consts.PWD, universal_newlines=True)
        p.communicate()
        if granularity == ida_consts.ENTRY_POINTS_GRANULARITY:
            entry_points = extract_functions_list(get_entry_points_addresses(module))
            all_functions = extract_functions_list(filter(lambda x: x != '', open(ida_out_file, "r").readlines()))
            exported_functions = map(lambda x: x[0].lower(), entry_points)
            funcs[image_name] = filter(lambda entry: entry[0].lower() in exported_functions, all_functions)
        elif granularity == ida_consts.DOMINATOR_GRANULARITY:
            map_file = os.path.join(ida_consts.DOMINATOR_TMP_DIR, "map.map")
            gdl_files = filter(lambda f: f.endswith("gdl"),
                               map(lambda f: os.path.join(ida_consts.DOMINATOR_TMP_DIR, f), os.listdir(ida_consts.DOMINATOR_TMP_DIR)))
            mapping = gdl2nx.read_map_file(map_file)
            for f in gdl_files:
                func_name = os.path.basename(f).split(".")[0]
                if func_name not in mapping:
                    continue
                tracing_addr = hex(int(mapping[func_name], 16) - int("400000", 16))
                if not tracing_addr in tracing_data[image_name]:
                    continue
                print func_name
                g = gdl2nx.gdl2gexf(f)
                dom = gdl2nx.get_dominance(g)
                labels = nx.get_node_attributes(g, "label")
                nodes_addrs = gdl2nx.get_labels_addrs(labels, mapping)
                dom_addrs = map(lambda key: (nodes_addrs[key], func_name,
                                             ida_consts.DOMINATOR_SEP.join(
                                                 map(lambda val: nodes_addrs[val], dom[key]))), dom)
                funcs.setdefault(image_name, []).extend(dom_addrs)
        else:
            funcs[image_name] = extract_functions_list(filter(lambda x: x!= '', open(ida_out_file,"r").readlines()))
    for image in funcs:
        breakpoints.extend(
                generate_breakpoints_list(funcs[image], image, granularity))
    return breakpoints


def create_bp_script_file(binaries, commands, granularity, tracing_data):
    """
    create script file that contains breakpoint for binary_file
    :param binaries: binaries to analyze
    :param commands: commands to append to bp
    """
    if ida_consts.STARTUP_SCRIPTS[granularity] is not None:
        return
    if granularity == ida_consts.DLL_GRANULARITY:
        commands.extend(".echo {BEGIN_BLOCK};lmf;.echo {END_BLOCK}".format(BEGIN_BLOCK=ida_consts.BEGIN_BREAKPOINT_BLOCK,
                                                                            END_BLOCK=ida_consts.END_BREAKPOINT_BLOCK).split(';'))
    print granularity, binaries
    ida_consts.STARTUP_SCRIPTS[granularity] = tempfile.mktemp(prefix=r"script_file_", dir=os.path.dirname(binaries[0]))
    init_tmp_dir(binaries[0])
    full_command_list = []
    modules_commands = []
    for binary in binaries:
        traces = get_bp_traces(binary, ida_consts.BREAK_ON_DLLS, granularity, tracing_data)
        partial_script = make_tmp_file(r"script_file_partial_")
        print partial_script
        with open(partial_script, "w") as f:
            f.write("\n".join(traces))
        if ".exe" in binary:
            full_command_list.append('$$>a<{0}'.format(partial_script))
        else:
            modules_commands.append((os.path.basename(binary).split(".")[0], partial_script.replace("\\","/")))
    if len(modules_commands) > 0:
        full_command_list.extend(ida_consts.get_break_on_dll_string(modules_commands))
    full_command_list.append(".echo {0}".format(ida_consts.BEGIN_TRACING))
    with open(ida_consts.STARTUP_SCRIPTS[granularity], "w") as f:
        f.write("\n".join(full_command_list + commands) + "\nq")
    print ida_consts.STARTUP_SCRIPTS[granularity]


def get_append_string(granularity):
    """
    :return: run script file command
    """
    return '$$>a<{0}'.format(ida_consts.STARTUP_SCRIPTS[granularity])


def run_cdb(binary_file, granularity):
    create_bp_script_file(binary_file, [], granularity)
    print (r'"{0}"  -o {1} -g -G  -c $<{2}'.format(ida_consts.CDB_EXE, binary_file, ida_consts.STARTUP_SCRIPT))
    p = subprocess.Popen(r'"{0}"  -o "{1}" -g -G  -c $<"{2}"'.format(ida_consts.CDB_EXE, binary_file, ida_consts.STARTUP_SCRIPT), stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=PWD)
    stdoutdata, stderrdata = p.communicate()
    print stdoutdata


def analyze_breakpoints(debugger_out):
    """
    return trace of this run
    :param debugger_out: file of debugger output
    :return:
    """
    breakpoints = filter(lambda x: ida_consts.BREAKPOINT_MAGIC in x, debugger_out)
    breakpoints = map(lambda x: x.replace(ida_consts.BREAKPOINT_MAGIC, ""), breakpoints)
    return breakpoints


if __name__ == "__main__":
    # print create_bp_script_file(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5511\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe", [])
        print create_bp_script_file(
            [r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5510-Copy\vulnerable\ImageMagick-Windows\VisualMagick\bin\im_mod_db_psd_.dll"],
            [],
            ida_consts.DOMINATOR_GRANULARITY,
            {'IM_MOD_DB_psd_'.lower(): [ '0x3420']})
    # print create_bp_script_file(r"C:\Users\User\Documents\Visual Studio 2015\Projects\Project1\Debug\Project1.exe", [])
