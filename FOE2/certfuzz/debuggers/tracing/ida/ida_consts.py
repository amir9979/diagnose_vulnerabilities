import os

current_path = os.path.realpath(__file__)
project_root = os.path.realpath(os.path.join(current_path, "..\..\..\..\..\.."))
IDA_EXE = r"c:\Program Files\IDA Demo 7.0\ida.exe"
IDA_SCRIPT = os.path.join(project_root, r"idc\dump_functions.idc")
IDA_CHUNKS_SCRIPT = os.path.join(project_root, r"idc\dump_chunks.idc")
IDA_XREFS_SCRIPT = os.path.join(project_root, r"idc\dump_xrefs.idc")
PWD = os.path.join(project_root, r"idc")
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x86\cdb.exe"
BREAKPOINT_MAGIC = r"BPMAGIC_"
BEGIN_BREAKPOINT_BLOCK = r"BEGIN_BLOCK"
END_BREAKPOINT_BLOCK = r"END_BLOCK"
BEGIN_TRACING = r"BEGIN_TRACING"
TMPS_DIR = ""
BREAK_ON_DLLS = False
DLL_DIAGNOSIS = True
DLL_GRANULARITY = "DLL"
ENTRY_POINTS_GRANULARITY = "ENTRY_POINT"
FUNCTION_GRANULARITY = "FUNCTION"
CHUNK_GRANULARITY = "CHUNK"
XREF_GRANULARITY = "XREF"
DLL_LOAD_ADDRESS = int('0x10000000', 16)
STARTUP_SCRIPTS = dict().fromkeys([DLL_GRANULARITY, ENTRY_POINTS_GRANULARITY, FUNCTION_GRANULARITY, CHUNK_GRANULARITY, XREF_GRANULARITY])
BREAK_ON_LOAD__IF_STRING = ".if ($sicmp(\\\"${module}\\\",\\\"MODULE_NAME\\\") == 0 & ${MODULE_NAME_ALIAS}) {$$>a<SCRIPT;.block{SET_ALIAS_FALSE}}"
BREAK_ON_LOAD__FOREACH_STRING = ".foreach (module {lm1m} ) {IF_CLAUSES}"
BREAK_ON_LOAD_STRING = "sxe -c \"FOREACH\" ld"
SET_ALIAS = "as /x ${/v:MODULE_NAME_ALIAS} VALUE"
ALIAS_FALSE = "0"
ALIAS_TRUE = "1"

def get_break_on_dll_string(module_commands):
    """
    :param module_commands: tuples of (module name, command to run)
    :return:  if len(module_commands) > 0 returns string of loads else return ""
    """
    define_aliases = []
    if_clauses = []
    for module_name, command in module_commands:
        SET_FALSE = SET_ALIAS.replace("MODULE_NAME", module_name).replace("VALUE", ALIAS_FALSE)
        define_aliases.append(SET_ALIAS.replace("MODULE_NAME", module_name).replace("VALUE", ALIAS_TRUE))
        if_clauses.append(BREAK_ON_LOAD__IF_STRING.replace("MODULE_NAME", module_name).replace("SCRIPT", command).replace("SET_ALIAS_FALSE", SET_FALSE))
    foreach = BREAK_ON_LOAD__FOREACH_STRING.replace("IF_CLAUSES", ";".join(if_clauses).replace("\\",""))
    return define_aliases + [foreach, BREAK_ON_LOAD_STRING.replace("FOREACH", BREAK_ON_LOAD__FOREACH_STRING.replace("IF_CLAUSES",
                                                                                                            ";".join(if_clauses)) + ";g")]
