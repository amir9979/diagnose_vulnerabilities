__author__ = 'amir'

import subprocess
import os

RADARE_EXE = r"C:\diagnose_vulnerabilities\radare2-w32-0.10.5\radare2.exe"
RADARE_PWD = r"C:\diagnose_vulnerabilities\radare2-w32-0.10.5"
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
TMP_FILE = r"c:\temp\startup_script.txt"
BREAKPOINT_MAGIC = r"ASDS_"

def extract_functions_list(radare_out):
    """
    extract functions list from radare output
    :param: radare_out - json of functions
    :return: list of functions to break on
    """
    return map(lambda x: x.split()[0], filter(lambda x : "fcn" in x, radare_out))


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
    p = subprocess.Popen(r'{0}  -c "aaaaa;afl;q" -q {1}'.format(RADARE_EXE, binary_file), stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=RADARE_PWD)
    stdoutdata, stderrdata = p.communicate()
    return generate_breakpoints_list(extract_functions_list(filter(lambda x: x!= '', stdoutdata.splitlines())))


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
    return '-c $<"{0}"'.format(TMP_FILE)

def run_cdb(binary_file):
    create_bp_script_file(binary_file, [])
    print (r'"{0}"  -o {1} -g -G  -c $<{2}'.format(CDB_EXE, binary_file, TMP_FILE))
    p = subprocess.Popen(r'"{0}"  -o "{1}" -g -G  -c $<"{2}"'.format(CDB_EXE, binary_file, TMP_FILE), stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_CONSOLE)
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
    print create_bp_script_file(r"C:\Windows\sysWOW64\notepad.exe", [])
