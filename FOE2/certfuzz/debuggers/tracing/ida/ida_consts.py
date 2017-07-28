import os

current_path = os.path.realpath(__file__)
project_root = os.path.realpath(os.path.join(current_path, "..\..\..\..\..\.."))
IDA_EXE = r"c:\Program Files (x86)\IDA Demo 6.95\idaq.exe"
IDA_SCRIPT = os.path.join(project_root, r"idc\dump_functions.idc")
PWD = os.path.join(project_root, r"idc")
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
STARTUP_SCRIPT = ""
BREAKPOINT_MAGIC = r"BPMAGIC_"
BEGIN_BREAKPOINT_BLOCK = r"BEGIN_BLOCK"
END_BREAKPOINT_BLOCK = r"END_BLOCK"
TMPS_DIR = ""
BREAK_ON_DLLS = False
DLL_DIAGNOSIS = True
DLL_GRANULARITY = "dll"
FUNCTION_GRANULARITY = "function"