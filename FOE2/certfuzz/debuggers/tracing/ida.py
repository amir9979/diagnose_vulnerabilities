__author__ = 'amir'

import subprocess
import os

IDA_EXE = r"c:\Program Files (x86)\IDA Demo 6.95\idaq.exe"
IDA_SCRIPT = r"C:\diagnose_vulnerabilities\idc\dump_functions.idc"
IDA_OUT_FILE = r"C:\diagnose_vulnerabilities\idc\functions.txt"
PWD = r"C:\diagnose_vulnerabilities\idc"
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
TMP_FILE = r"c:\temp\startup_script.txt"
DB_FILE = r"c:\temp\db.idb"
BREAKPOINT_MAGIC = r"BPMAGIC_"

def extract_functions_list(ida_out):
    """
    extract functions list from script output
    :param: radare_out - json of functions
    :return: list of functions to break on
    """
    return map(lambda x: x.split("=")[0], ida_out)


def generate_breakpoints_list(addrs):
    """
    generate list of breakpoints to windbg
    :param addrs: list of addresses
    :return: str of one time trace breakpoints
    """
    return map(lambda addr: r'bp /1 {0} ".echo {1}{0};g"'.format(addr, BREAKPOINT_MAGIC), addrs)

def get_bp_traces(binary_file):
    """
    run radare to extract breakpoints to functions
    :param binary_file: path to binary file to use
    :return: list of traces
    """
    command = r'"{0}" -T"Portable executable for 80386" -R -o"C:\Temp\db.idb" -S"{1}" "{2}"'.format(IDA_EXE, IDA_SCRIPT, binary_file)
    print command
    subprocess.Popen(command, stdout=open(os.devnull), stderr=open(os.devnull),
                  cwd=PWD , universal_newlines=True)
    return generate_breakpoints_list(extract_functions_list(filter(lambda x: x!= '', open(IDA_OUT_FILE,"r").readlines())))


def create_bp_script_file(binary_file, commands):
    """
    create script file that contains breakpoint for binary_file
    :param binary_file: program to analyze
    :param commands: commands to append to bp
    """
    with open(TMP_FILE, "w") as f:
        f.write("\n".join(get_bp_traces(binary_file) + commands) + "\ng\n")

def get_append_string():
    """
    :return: run script file command
    """
    return '$$<{0}'.format(TMP_FILE)

def run_cdb(binary_file):
    create_bp_script_file(binary_file, [])
    print (r'"{0}"  -o {1} -g -G  -c $<{2}'.format(CDB_EXE, binary_file, TMP_FILE))
    p = subprocess.Popen(r'"{0}"  -o "{1}" -g -G  -c $<"{2}"'.format(CDB_EXE, binary_file, TMP_FILE), stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_CONSOLE, cwd=PWD)
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
    print create_bp_script_file(r"E:\notepad\notepad.exe", [])
