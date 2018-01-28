__author__ = 'amir'

import os
import csv
import glob
import pefile
from  FOE2.certfuzz.debuggers.tracing.ida.ida_consts import BEGIN_BREAKPOINT_BLOCK, END_BREAKPOINT_BLOCK, BEGIN_TRACING
try:
    from SFL_diagnoser.Diagnoser.diagnoserUtils import write_planning_file
except:
    from sfl_diagnoser.Diagnoser.diagnoserUtils import write_planning_file

BREAKPOINT_MAGIC = r"BPMAGIC_"
EXPLOITABILITY_START = r"Exploitability Classification: "
EXPLOITABILITY_ENUM = {"NOT_AN_EXCEPTION" : 0, "PROBABLY_NOT_EXPLOITABLE" : 1, "PROBABLY_EXPLOITABLE" : 1, "EXPLOITABLE" : 1, "UNKNOWN" : 1}
FUNCS_DICT = {}

def funcs_to_dlls(msec_file_output, binary_file, split_by_dll):
    global FUNCS_DICT
    if split_by_dll:
        breakpoints, exploit_class = msec_file_output
        init_func_dict(binary_file)
        dll_brekpoints = set()
        for bp in breakpoints:
            dll_brekpoints.add(FUNCS_DICT.get(bp, bp))
        return list(dll_brekpoints), exploit_class
    else:
        return msec_file_output


def init_func_dict(binary_file):
    global FUNCS_DICT
    if len(FUNCS_DICT) == 0:
        pe = pefile.PE(binary_file)
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                FUNCS_DICT[func.name] = entry.dll
                FUNCS_DICT["_" + func.name] = entry.dll
                FUNCS_DICT["__" + func.name] = entry.dll


def get_matrix_for_campaign(campaign_dir, functions_file, binary_file, split_by_dll, out_file):
    all_funcs = read_function_list(functions_file)
    all_funcs_dlls = funcs_to_dlls((all_funcs, 0), binary_file, split_by_dll)[0]
    print all_funcs
    print all_funcs_dlls
    cases = []
    for root, dirs, files in os.walk(campaign_dir):
        for d in dirs:
            if "iteration_" not in d:
                continue
            crash_dir = filter(lambda dir: "foe-crash" in dir , glob.glob(os.path.join(root, d, "*")))[0]
            msec_file = glob.glob(os.path.join(crash_dir, "*.msec"))[0]
            cases.append(funcs_to_dlls(get_functions_traces(msec_file), binary_file, split_by_dll))
        return write_matrix_to_file(all_funcs_dlls, [], cases, out_file)


def filter_known_dlls(modules_list):
    known_dlls = ["kernel_appcore", "KERNEL32", "shlwapi", 'windows_storage', 'msvcrt', 'WINMMBASE_e60000', 'DNSAPI',
                  'RPCRT4', 'ADVAPI32', 'WINMMBASE_13c0000', 'WINMMBASE_a40000', 'WINMMBASE', 'powrprof',
                  'WINMMBASE_cf0000', 'WINMMBASE_f20000', 'WINMMBASE_1800000', 'WINMMBASE_10b0000', 'VCOMP140D',
                  'WINMMBASE_1520000', 'WINMMBASE_1020000', 'WINMMBASE',
                  'IMM32', 'USER32', 'combase', 'ole32', 'WINMMBASE_71c70000', 'VCRUNTIME140D',
                  'ucrtbased', 'ntdll', 'shcore',  'CRYPTBASE', 'SHELL32', 'WINMMBASE_1730000',
                  'KERNELBASE', 'gdi32full', 'WINMM', 'sechost', 'SspiCli', 'IPHLPAPI', 'GDI32',
                  'WINMMBASE_780000', 'WINMMBASE', 'win32u', 'ucrtbase', 'bcryptPrimitives',
                  'WINMMBASE_1790000', 'profapi', 'cfgmgr32', 'NSI', "WS2_32", 'rsaenh', 'winmmbase'
                    , 'CRYPTSP', 'bcrypt', 'USP10.dll', 'winhttp', 'ondemandconnroutehelper'
        , 'apphelp', 'MSIMG32.dll', "msasn1", "oleaut32", "psapi", "comctl32", "avicap32", "crypt32",
                  "msvfw32", "ffmpeg", "msvcp_win", "core_db_glib_", "core_db_zlib_", "dbghelp", "name",
                  'vcruntime140', 'libpng12', 'zlib1', 'kernel.appcore', 'jpeg62', 'clang_rt.asan_dynamic-i386',
                  'wsock32', 'charset', 'iconv', 'libxml2', 'zlib', 'msvcr90', 'bzip2', 'asan', 'crt', 'scrt']
    dlls = map(str.lower, known_dlls + map(lambda x: x.replace(".dll", ""), known_dlls))
    return filter(lambda x: all(map(lambda y: y not in x, dlls)), modules_list)

def get_matrix_for_dll_diagnosing(campaign_dir, out_file):
    all_dlls = set()
    cases = []
    for root, dirs, files in os.walk(campaign_dir):
        for d in dirs:
            if "iteration_" not in d:
                continue
            crash_dir = filter(lambda dir: "foe-crash" in dir , glob.glob(os.path.join(root, d, "*")))[0]
            try:
                msec_file = glob.glob(os.path.join(crash_dir, "*.msec"))[0]
                modules, exploitability = get_loaded_modules_traces(msec_file)
                modules = filter_known_dlls(modules)
                all_dlls = all_dlls.union(modules)
                cases.append((modules, exploitability))
            except:
                pass
        dlls_list = list(all_dlls)
        print dlls_list
        return write_matrix_to_file(dlls_list, [], cases, out_file)


def read_function_list(functions_file):
    with open(functions_file) as f:
        return map(lambda line: line.replace("\n","").split("=")[1], f.readlines())

def get_functions_traces(msec):
    """
    get activity vector and obs for msec instance
    activity vector is list of breakpoints
    obs is exploitability of instance
    :param msec: log of cdb output
    """
    with open(msec) as f:
        lines = map(lambda line: line.replace("\n","") , f.readlines())
        break_points = filter(lambda line: line.startswith(BREAKPOINT_MAGIC), lines)
        break_points = map(lambda bp: bp.replace(BREAKPOINT_MAGIC, "") , break_points)
    return break_points, get_exploitability_of_instance(msec)

def get_loaded_modules_traces(msec):
    """
    get activity vector and obs for msec instance
    activity vector is list of breakpoints
    obs is exploitability of instance
    :param msec: log of cdb output
    """
    loaded_modules = set()
    with open(msec) as f:
        # content = "".join(filter(lambda line:  not line.startswith("0:000>"), f.readlines()))
        content = f.read()
        content = content.split(BEGIN_TRACING)[1]
        blocks = map(lambda block: block.split(END_BREAKPOINT_BLOCK)[0], content.split(BEGIN_BREAKPOINT_BLOCK)[1:])
        modules = map(lambda comp: filter(lambda c: c!='',comp) ,map(lambda block: block.lower().split('\n'), blocks))
        modules = map(lambda x: map(lambda y: y.split()[-1], x), modules)
        modules = filter(lambda module: len(module) > 0, modules)
        for module_list in modules:
            loaded_modules = loaded_modules.union(set(module_list))
    return loaded_modules, get_exploitability_of_instance(msec)

def get_exploitability_of_instance(instance_file):
    """
    :param instance_file: msec file
    :return: exploitability of instance
    """
    with open(instance_file) as f:
        try:
            exploitability = filter(lambda line: line.startswith(EXPLOITABILITY_START), f.readlines())[0].replace(EXPLOITABILITY_START, "").replace("\n", "")
            return EXPLOITABILITY_ENUM[exploitability]
        except:
            return EXPLOITABILITY_ENUM["NOT_AN_EXCEPTION"]


def write_matrix_to_file(all_funcs, bugs, cases, out_file, description = ""):
    cases_ids, cases_traces = cases_rows(all_funcs, cases)
    lines = [["[Description]"]] + [[description]]
    lines += [["[Priors]"]] +[ [",".join([str(0.1) for _ in all_funcs])]]
    lines += [["[Bugs]"]] + [bugs]
    lines += [["[InitialTests]"]] + cases_ids
    lines += [["[TestDetails]"]] + cases_traces
    with open(out_file, 'wb') as f:
        writer = csv.writer(f,delimiter=";")
        writer.writerows(lines)


def cases_rows(all_funcs,cases):
    dets = []
    ids = []
    for ind,(breakpoints, obs) in enumerate(cases):
        breakpoints_ids = sorted(map(lambda bp: all_funcs.index(bp), breakpoints))
        dets.append([ind,breakpoints_ids,breakpoints_ids,obs])
        ids.append([ind])
    return ids,dets

def create_matrix_for_dir(examples_path, bugged_path, matrix_path, files_to_read=None):
    cases = []
    for msec_file in glob.glob(os.path.join(examples_path, "*.msec"))[:files_to_read]:
        try:
            modules, exploitability = get_loaded_modules_traces(msec_file)
            modules = filter_known_dlls(modules)
            cases.append((os.path.basename(msec_file), modules, exploitability))
        except:
            print "fail load file", msec_file
    bugs = []
    if bugged_path != None:
        with open(bugged_path) as f:
            lines = f.readlines()
            bugs = map(lambda line: str.lower(line).replace("\n","").replace(" ","").replace(".dll",""), lines)
    write_planning_file(matrix_path, bugs, cases)

if __name__ == "__main__":
    create_matrix_for_dir(r"C:\Temp\examples", r"c:\temp\examples.txt")
    exit()
    get_matrix_for_dll_diagnosing(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing\working_dir\campaign_2mvfqv",
                                  r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing\matrix.txt")
    exit()
    get_matrix_for_campaign(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing\working_dir\campaign_b09tqg",
                            r"C:\Temp\windbg_functions\vulnerabilities_ImageMagick_exploited_CVE-2017-5509_vulnerable_ImageMagick-Windows_VisualMagick_bin_magick.exe\out_file_magick.exe_lasvtl",
                            r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe",
                            True,
                            r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing\matrix.txt")