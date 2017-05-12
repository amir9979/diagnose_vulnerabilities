__author__ = 'amir'

import subprocess
import tempfile
import pefile
import os


current_path = os.path.realpath(__file__)
project_root = os.path.realpath(os.path.join(current_path, "..\..\..\..\.."))

IDA_EXE = r"c:\Program Files (x86)\IDA Demo 6.95\idaq.exe"
IDA_SCRIPT = os.path.join(project_root, r"idc\dump_functions.idc")
PWD = os.path.join(project_root, r"idc")
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
STARTUP_SCRIPT = ""
DB_FILE = tempfile.mkstemp(prefix=r"db_file_",dir=r"C:\temp\windbg_functions")[1]
BREAKPOINT_MAGIC = r"BPMAGIC_"


already_imported_modules = []

def getImportedModules(pe_file_to_analyze):
    global already_imported_modules
    if not os.path.exists(pe_file_to_analyze):
        return []
    pe = pefile.PE(pe_file_to_analyze)
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        path = os.path.join(os.path.dirname(pe_file_to_analyze), entry.dll)
        if os.path.exists(path) and path not in already_imported_modules:
            already_imported_modules.append(path)
            getImportedModules(path)
    return already_imported_modules


def extract_functions_list(ida_out):
    """
    extract functions list from script output
    :param: radare_out - json of functions
    :return: list of functions to break on
    """
    return map(lambda x: x.replace("\n", "").split("="), ida_out)


def generate_breakpoints_list(addrs, image_name):
    """
    generate list of breakpoints to windbg
    :param addrs: list of addresses
    :return: str of one time trace breakpoints
    """
    return map(lambda addr: r'bu /1 {0} + {1} ".echo {2}{3}{2};g"'.format(image_name, addr[0], BREAKPOINT_MAGIC, addr[1]), addrs)

def get_bp_traces(binary_file):
    """
    run radare to extract breakpoints to functions
    :param binary_file: path to binary file to use
    :return: list of traces
    """
    modules = getImportedModules(binary_file)
    breakpoints = []
    for pe in modules:
        image_name = os.path.basename(pe).split(".")[0]
        ida_out_file = tempfile.mkstemp(prefix=r"out_file_", dir=r"C:\temp\windbg_functions")[1]
        ida_call_script = "{0} {1} {2}".format(IDA_SCRIPT, ida_out_file, os.path.basename(pe).split(".")[1])
        command = r'"{0}" -T"Portable executable for 80386" -R -o"{1}" -S"{2}" "{3}"'.format(IDA_EXE, DB_FILE, ida_call_script, pe)
        print command
        p = subprocess.Popen(command, stdout=open(os.devnull), stderr=open(os.devnull),
                  cwd=PWD , universal_newlines=True)
        p.communicate()
        breakpoints.extend(
            generate_breakpoints_list(
                extract_functions_list(filter(lambda x: x!= '', open(ida_out_file,"r").readlines())), image_name))
    return breakpoints


def create_bp_script_file(binary_file, commands):
    """
    create script file that contains breakpoint for binary_file
    :param binary_file: program to analyze
    :param commands: commands to append to bp
    """
    global STARTUP_SCRIPT
    if os.path.exists(STARTUP_SCRIPT):
        return
    STARTUP_SCRIPT = tempfile.mkstemp(prefix=r"script_file_", dir=os.path.dirname(binary_file))[1]
    print STARTUP_SCRIPT
    traces = get_bp_traces(binary_file) + commands
    all_bps = tempfile.mkstemp(prefix=r"all_bps_", dir=os.path.dirname(binary_file))[1]
    with open(all_bps, "w") as f:
        f.write("\n".join(traces))
    full_command_list = []
    for i in range(0, len(traces), 500):
        current_traces= traces[i:i + 500]
        partial_script = tempfile.mkstemp(prefix=r"script_file_partial_", dir=os.path.dirname(binary_file))[1]
        with open(partial_script, "w") as f:
            f.write("\n".join(current_traces))
        full_command_list.append('$$<{0}'.format(partial_script))
    with open(STARTUP_SCRIPT, "w") as f:
        f.write("\n".join(full_command_list) + "\ng\n")

def get_append_string():
    """
    :return: run script file command
    """
    return '$$<{0}'.format(STARTUP_SCRIPT)

def run_cdb(binary_file):
    create_bp_script_file(binary_file, [])
    print (r'"{0}"  -o {1} -g -G  -c $<{2}'.format(CDB_EXE, binary_file, STARTUP_SCRIPT))
    p = subprocess.Popen(r'"{0}"  -o "{1}" -g -G  -c $<"{2}"'.format(CDB_EXE, binary_file, STARTUP_SCRIPT), stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=PWD)
    stdoutdata, stderrdata = p.communicate()
    print stdoutdata

def analyze_breakpoints(debugger_out):
    """
    return trace of this run
    :param debugger_out: file of debugger output
    :return:
    """
    breakpoints = filter(lambda x: BREAKPOINT_MAGIC in x, debugger_out)
    breakpoints = map(lambda x: x.replace(BREAKPOINT_MAGIC, ""), breakpoints)
    return breakpoints


if __name__ == "__main__":
    print create_bp_script_file(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe", [])
