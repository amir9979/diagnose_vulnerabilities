__author__ = 'amir'

import os
import csv
import glob

BREAKPOINT_MAGIC = r"BPMAGIC_"
EXPLOITABILITY_START = r"Exploitability Classification: "
EXPLOITABILITY_ENUM = {"UNKNOWN" : 0, "Probably Not Exploitable" : 1, "Probably Exploitable" : 2, "Exploitable" : 3}

def get_matrix_for_campaign(campaign_dir, functions_file, out_file):
    all_funcs = read_function_list(functions_file)
    cases = []
    for root, dirs, files in os.walk(campaign_dir):
        for d in dirs:
            if "iteration_" not in d:
                continue
            crash_dir = filter(lambda dir: "foe-crash" in dir , glob.glob(os.path.join(root, d, "*")))[0]
            msec_file = glob.glob(os.path.join(crash_dir, "*.msec"))[0]
            cases.append(read_msec_file(msec_file))
        return write_matrix_to_file(all_funcs, cases, out_file)


def read_function_list(functions_file):
    with open(functions_file) as f:
        return map(lambda line: line.split("=")[0], f.readlines())

def read_msec_file(msec):
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
        return break_points, get_exploitability_of_instance(lines)

def get_exploitability_of_instance(instance):
    """
    :param instance: lines of msec file
    :return: exploitability of instance
    """
    exploitability = filter(lambda line: line.startswith(EXPLOITABILITY_START), instance)[0].replace(EXPLOITABILITY_START, "")
    return EXPLOITABILITY_ENUM[exploitability]


def write_matrix_to_file(all_funcs, cases, out_file):
    cases_ids, cases_traces = cases_rows(all_funcs, cases)
    lines=[["[Priors]"]] + [[0.1 for f in all_funcs]]
    lines += [["[Bugs]"]] + [[]]
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

if __name__ == "__main__":
    get_matrix_for_campaign(r"C:\diagnose_vulnerabilities\FOE2\notepad\working_dir\campaign_xiqetq",
                            r"C:\diagnose_vulnerabilities\idc\functions_notepad.txt",
                            r"C:\diagnose_vulnerabilities\FOE2\notepad\working_dir\campaign_xiqetq\instance.txt")