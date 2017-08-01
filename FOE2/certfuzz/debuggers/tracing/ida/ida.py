import ida_consts

__author__ = 'amir'

import collections
import os
import subprocess
import tempfile

import pefile

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


def extract_functions_list(ida_out, granularity='CHUNK'):
    """
    extract functions list from script output
    :param: radare_out - json of functions
    :param: granularity - FUNCTION or CHUNK
    :return: list of functions to break on
    """
    return map(lambda x: x.replace("\n", "").split("="), filter(lambda line: granularity in line, ida_out))

def get_command_on_breakpoint(address, image_name, granularity = ida_consts.DLL_GRANULARITY):
    command = []
    if granularity == ida_consts.DLL_GRANULARITY:
        command.append(".echo {0}".format(ida_consts.BEGIN_BREAKPOINT_BLOCK))
        command.append("lm1m")
        command.append(".echo {0}".format(ida_consts.END_BREAKPOINT_BLOCK))
    elif granularity == ida_consts.FUNCTION_GRANULARITY:
        command.append(".echo {0}{1}{2}".format(ida_consts.BEGIN_BREAKPOINT_BLOCK, address, ida_consts.END_BREAKPOINT_BLOCK))

    command.append('g')
    return ";".join(command)

def generate_breakpoints_list(addrs, image_name, granularity):
    """
    generate list of breakpoints to windbg
    :param addrs: list of addresses
    :return: str of one time trace breakpoints
    """
    return map(lambda addr: r'bu /1 {0} + {1} "{2}"'.format(image_name, addr[0], get_command_on_breakpoint(addr[1], image_name, granularity)), addrs)

def create_breakpoint_list_for_modules(modules):
    return map(lambda module: r'bm /1 {0}!* ".echo {1};k 1; .echo {2};g"'.format(os.path.basename(module).split(".")[0],
                                                                                 ida_consts.BEGIN_BREAKPOINT_BLOCK,
                                                                                 ida_consts.END_BREAKPOINT_BLOCK), modules)

def get_ida_script_and_params(granularity, ida_out_file, module_name, tracing_data):
    if granularity == ida_consts.CHUNK_GRANULARITY and module_name in tracing_data:
        functions_file = tempfile.mktemp()
        with open(functions_file, "wb") as f:
            f.writelines(tracing_data[module_name])
        return "{0} {1} {2} {3}".format(ida_consts.IDA_CHUNKS_SCRIPT, functions_file, ida_out_file,
                                        module_name.split(".")[1])
    else:
        return "{0} {1} {2}".format(ida_consts.IDA_SCRIPT, ida_out_file, module_name.split(".")[1])


def get_bp_traces(binary_file, break_on_dlls, granularity, tracing_data):
    """
    run radare to extract breakpoints to functions
    :param binary_file: path to binary file to use
    :return: list of traces
    """
    modules = getImportedModules(binary_file)
    # return create_breakpoint_list_for_modules(modules)
    breakpoints = []
    funcs = {}
    for module in modules:
        image_name = os.path.basename(module)
        ida_out_file = make_tmp_file(r"out_file_" + image_name.replace(".dll", "") + "_")
        ida_call_script = get_ida_script_and_params(granularity, ida_out_file, os.path.basename(module), tracing_data)
        db_file = make_tmp_file(r"db_file_")
        command = r'"{0}" -T"Portable executable for 80386" -R -o"{1}" -S"{2}" "{3}"'.format(ida_consts.IDA_EXE, db_file, ida_call_script, module)
        print command
        p = subprocess.Popen(command, stdout=open(os.devnull), stderr=open(os.devnull),
                             cwd=ida_consts.PWD, universal_newlines=True)
        p.communicate()
        funcs[image_name] = extract_functions_list(filter(lambda x: x!= '', open(ida_out_file,"r").readlines()))
    if break_on_dlls:
        for image in funcs:
            breakpoints.extend(
                    generate_breakpoints_list(funcs[image], image, granularity))
    else:
        image = os.path.basename(binary_file)
        breakpoints.extend(
            generate_breakpoints_list(funcs[image], image, granularity))
    all_funcs = []
    for image in funcs:
        all_funcs.extend([x[1] for x in funcs[image]])
    print all_funcs
    print len(all_funcs)
    print len(set(all_funcs))
    dup = collections.Counter(all_funcs)
    d = [item for item, count in dup.items() if count == len(modules)]
    print "duplicates: ",len(d), dup
    return breakpoints


def create_bp_script_file(binary_file, commands, granularity, tracing_data):
    """
    create script file that contains breakpoint for binary_file
    :param binary_file: program to analyze
    :param commands: commands to append to bp
    """
    if os.path.exists(ida_consts.STARTUP_SCRIPT):
        return
    ida_consts.STARTUP_SCRIPT = tempfile.mktemp(prefix=r"script_file_", dir=os.path.dirname(binary_file))
    init_tmp_dir(binary_file)
    print ida_consts.STARTUP_SCRIPT
    traces = get_bp_traces(binary_file, ida_consts.BREAK_ON_DLLS, granularity, tracing_data)
    all_bps = make_tmp_file(r"all_bps_")
    with open(all_bps, "w") as f:
        f.write("\n".join(traces))
    full_command_list = []
    for i in range(0, len(traces), 500):
        current_traces= traces[i:i + 500]
        partial_script = make_tmp_file(r"script_file_partial_")
        with open(partial_script, "w") as f:
            f.write("\n".join(current_traces))
        if ".exe" in binary_file:
            full_command_list.append('$$<{0}'.format(partial_script))
        else:
            break_on_load = "sxe -c \"$$>a<{SCRIPT};g\" ld:{MODULE}".format(SCRIPT=partial_script.replace("\\","/"), MODULE=os.path.basename(binary_file))
            full_command_list.append(break_on_load)
    with open(ida_consts.STARTUP_SCRIPT, "w") as f:
        f.write("\n".join(full_command_list + commands) + "\ng\nq")

def get_append_string():
    """
    :return: run script file command
    """
    return '$$>a<{0}'.format(ida_consts.STARTUP_SCRIPT)

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
            r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5511\vulnerable\ImageMagick-Windows\VisualMagick\bin\IM_MOD_DB_psd_.dll",
            [],
            ida_consts.CHUNK_GRANULARITY,
            {"IM_MOD_DB_psd_.dll" : "0x10009890"})
    # print create_bp_script_file(r"C:\Users\User\Documents\Visual Studio 2015\Projects\Project1\Debug\Project1.exe", [])
