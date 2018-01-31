import sys
from SFL_diagnoser.Diagnoser.ExperimentInstance import ExperimentInstance
from SFL_diagnoser.Diagnoser.Experiment_Data import Experiment_Data
from SFL_diagnoser.Diagnoser.Diagnosis import Diagnosis
import SFL_diagnoser.Diagnoser.ExperimentInstance
from SFL_diagnoser.Diagnoser.diagnoserUtils import readPlanningFile, save_ds_to_matrix_file, write_merged_matrix
from SFL_diagnoser.Diagnoser.Diagnosis_Results import Diagnosis_Results
import diagnoser.campaign_matrix
import os
import csv
import tempfile
import consts

def calc_result_fo_planning_file(planning_file, out_file):
    global instance
    instance = readPlanningFile(planning_file)
    precision, recall = instance.calc_precision_recall()
    csv_output = [["precision", "recall"], [precision, recall]]
    print planning_file , precision, recall
    with open(out_file, "wb") as f:
        writer = csv.writer(f)
        writer.writerows(csv_output)


def dll_diagnosis(matrix_file_name="dll_diagnosis.txt", result_file_name="dll_diagnosis_result.txt"):
    for dir_name in ["CVE-2016-7531", "CVE-2016-7533", "CVE-2016-8866", "CVE-2017-5506", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510",
                     "CVE-2017-5511"]:
        fuzzing_dir = os.path.join(r"C:\vulnerabilities\ImageMagick_exploited", dir_name, "fuzzing")
        planning_file = os.path.join(fuzzing_dir, matrix_file_name)
        out_file = os.path.join(fuzzing_dir, result_file_name)
        try:
            calc_result_fo_planning_file(planning_file, out_file)
        except:
            print "failed", planning_file

def xref_to_function(xref):
    if "$" in xref:
        return xref.split("$")[1]
    else:
        return xref

def xref_diagnose(xref_instance):
    components_indices = range(max(reduce(list.__add__, SFL_diagnoser.Diagnoser.ExperimentInstance.POOL.values())))
    components = list(set([xref_to_function(SFL_diagnoser.Diagnoser.ExperimentInstance.COMPONENTS_NAMES[x]) for x in
                           components_indices]))
    bugged_components = [xref_to_function(SFL_diagnoser.Diagnoser.ExperimentInstance.COMPONENTS_NAMES[b]) for b in SFL_diagnoser.Diagnoser.ExperimentInstance.BUGS]
    validComps = [x for x in components if x not in bugged_components]
    recall_accum = 0
    precision_accum = 0
    for d in xref_instance.get_named_diagnoses():
        diagnosis = map(xref_to_function, d.diagnosis)
        p = d.probability
        precision, recall = ExperimentInstance.precision_recall_diag(bugged_components, diagnosis, p, validComps)
        if(recall!="undef"):
            recall_accum=recall_accum+recall
        if(precision!="undef"):
            precision_accum=precision_accum+precision
    return precision_accum,recall_accum

def get_instance_results(planning_file):
    """
    return the following results for the planning file:
        precision
        recall
        wasted
        #comps
        #failed comps
    """
    instance = readPlanningFile(planning_file)
    precision, recall = instance.calc_precision_recall()
    wasted = instance.calc_wasted_components()
    ds = instance.initials_to_DS()
    comps_num = len(ds.get_components())
    failed_comps = len(ds.get_components_in_failed_tests())


def summarize_results(cve_list, bugged_dll_file, bugged_function_file, dll_matrix, function_matrix, xref_matrix, results_file_name):
    header = ["cve_number", "bugged_dll", "bugged_function", "dll_precision", "dll_recall", "dll_comps_number",
              "dll_failed_number", "function_precision",
              "function_recall", "xref_precision", "xref_recall"]
    csv_lines = [header]
    for cve in cve_list:
        fuzzing_dir = os.path.join(r"C:\vulnerabilities\ImageMagick_exploited", cve, "fuzzing")
        bugged_dll = open(os.path.join(fuzzing_dir, bugged_dll_file)).read().replace("\n", "")
        bugged_function = open(os.path.join(fuzzing_dir, bugged_function_file)).read().replace("\n", "")
        dll_instance = readPlanningFile(os.path.join(fuzzing_dir, dll_matrix))
        dll_precision, dll_recall = dll_instance.calc_precision_recall()
        function_precision, function_recall = readPlanningFile(os.path.join(fuzzing_dir, function_matrix)).calc_precision_recall()
        xref_precision, xref_recall = xref_diagnose(readPlanningFile(os.path.join(fuzzing_dir, xref_matrix)))
        csv_lines.append([cve, bugged_dll, bugged_function, dll_precision, dll_recall,function_precision,
                          function_recall, xref_precision, xref_recall])
    with open(results_file_name, "wb") as f:
        writer = csv.writer(f)
        writer.writerows(csv_lines)

def get_results_objects_for_instance(instance_to_diagnose, sep):
    optimized_matrix = tempfile.mktemp(prefix="optimized_")
    reduced_matrix = tempfile.mktemp(prefix="reduced_")
    merged_matrix = tempfile.mktemp(prefix="merged_")
    merged_reduced_matrix = tempfile.mktemp(prefix="merged_reduced_")

    save_ds_to_matrix_file(instance_to_diagnose.initials_to_DS().optimize(), optimized_matrix)
    optimized_instance = readPlanningFile(optimized_matrix)
    optimized_instance.diagnose()
    optimized_results = get_results_by_sep(optimized_instance, sep)
    save_ds_to_matrix_file(optimized_instance.initials_to_DS().remove_duplicate_tests(), reduced_matrix)
    write_merged_matrix(optimized_instance, merged_matrix)
    reduced_instance = readPlanningFile(reduced_matrix)
    reduced_instance.diagnose()
    reduced_results = get_results_by_sep(reduced_instance, sep)

    merged_instance = readPlanningFile(merged_matrix)
    merged_instance.diagnose()
    merged_results = get_results_by_sep(merged_instance, sep)

    save_ds_to_matrix_file(merged_instance.initials_to_DS().remove_duplicate_tests(), merged_reduced_matrix)
    merged_reduced_instance = readPlanningFile(merged_reduced_matrix)
    merged_reduced_instance.diagnose()
    merged_reduced_results = get_results_by_sep(merged_reduced_instance, sep)

    return optimized_results, reduced_results, merged_results, merged_reduced_results


def full_results(base_dir, cve_list, dll_matrix_file_name=consts.DLL_MATRIX,
                 function_matrix_file_name=consts.FUNCTION_MATRIX,
                 dominator_matrix_file_name=consts.DOMINATOR_MATRIX,
                 xref_matrix_file_name=consts.XREF_MATRIX,
                 results_file_name=None):
    header = ["cve_number", "granularity", "matrix_type"]
    csv_lines = []
    added_results_header = False
    for cve in cve_list:
        fuzzing_dir = os.path.join(base_dir, cve, "fuzzing")
        dll_matrix = os.path.join(fuzzing_dir, dll_matrix_file_name)
        function_matrix = os.path.join(fuzzing_dir, function_matrix_file_name)
        dominator_matrix = os.path.join(fuzzing_dir, dominator_matrix_file_name)
        xref_matrix = os.path.join(fuzzing_dir, xref_matrix_file_name)
        for granularity, instance_file, sep in zip(["dll", "function", "dominator", "code blocks"], [dll_matrix, function_matrix, dominator_matrix, xref_matrix], [None, "&", "&", "&"]):
        # for granularity, instance_file, sep in zip(["dll", "entry_points", "function", "xref"], [dll_matrix, entry_matrix, function_matrix, xref_matrix], [None, None, None, "$"]):
            print cve, granularity
            if not os.path.exists(instance_file):
                continue
            csv_lines.extend(instance_diagnosis(added_results_header, cve, granularity, header, readPlanningFile(instance_file), sep))
            added_results_header = True
    with open(results_file_name, "wb") as f:
        writer = csv.writer(f)
        writer.writerows(csv_lines)


def instance_diagnosis(added_results_header, cve_id, granularity, header, instance_to_diagnose, sep, additional_data=[]):
    csv_lines = []
    if 1 == 1:
    try:
        base_results, reduced_results, merged_results, merged_reduced_results = get_results_objects_for_instance(
            instance_to_diagnose, sep)
        if not added_results_header:
            header += base_results.get_metrics_names()
            csv_lines.append(header)
        csv_lines.append([cve_id, granularity, "base"] + additional_data + base_results.get_metrics_values())
        csv_lines.append([cve_id, granularity, "remove_duplicate_tests"] + additional_data + reduced_results.get_metrics_values())
        csv_lines.append([cve_id, granularity, "merge_same_comps"] + additional_data + merged_results.get_metrics_values())
        csv_lines.append(
            [cve_id, granularity, "remove_duplicate_tests&merge_same_comps"] + additional_data + merged_reduced_results.get_metrics_values())
        return csv_lines
    # except:
    #     pass
    except:
        return []


def check_fuzzing_for_dir(working_dir, results_file, number_files_to_read, matrix_path, sep):
    results = []
    for number in number_files_to_read:
        diagnoser.campaign_matrix.create_matrix_for_dir(working_dir, results_file, matrix_path, number)
        base_results, reduced_results, merged_results, merged_reduced_results = get_results_objects_for_instance(matrix_path, sep)
        results.append([number, base_results.precision, base_results.recall, base_results.wasted, base_results.num_comps, reduced_results.num_tests])
    return results

def check_fuzzing_influence(base_dir, cves, dll_matrix_file_name=consts.DLL_MATRIX,
                 function_matrix_file_name=consts.FUNCTION_MATRIX,
                 dominator_matrix_file_name=consts.DOMINATOR_MATRIX,
                 xref_matrix_file_name=consts.XREF_MATRIX, results_file_name=None):
    number_files_to_read = [20, 50, 100, 250 , 400]
    tmp_matrix = tempfile.mktemp(dir=r"C:\temp", prefix="tmp_matrix")
    print tmp_matrix
    header = ["cve_number", "granularity", "matrix_type", "fuzzing_files"]
    csv_lines = []
    added_results_header = False
    for cve in cves:
        fuzzing_dir = os.path.join(base_dir, cve, "fuzzing")
        if not os.path.exists(fuzzing_dir):
            continue
        dll_matrix = os.path.join(fuzzing_dir, dll_matrix_file_name)
        function_matrix = os.path.join(fuzzing_dir, function_matrix_file_name)
        # dominator_matrix = os.path.join(fuzzing_dir, dominator_matrix_file_name)
        xref_matrix = os.path.join(fuzzing_dir, xref_matrix_file_name)
        for granularity, instance_file, sep in zip(["dll", "function", "code blocks"],
                                                   [dll_matrix, function_matrix, xref_matrix],
                                                   [None, None, "$", "$"]):
            for number in number_files_to_read:
                instance = readPlanningFile(instance_file)
                instance.initial_tests = instance.initial_tests[:number]
                print cve, granularity, number
                csv_lines.extend(
                    instance_diagnosis(added_results_header, cve, granularity, header, instance, sep, [number]))
                added_results_header = True
        with open(results_file_name, "wb") as f:
            writer = csv.writer(f)
            writer.writerows(csv_lines)

def get_results_by_sep(instance, seperator=None):
    def filter_comps(xref_comp):
        return seperator in xref_comp
    def xref_comp_to_function(xref_comp):
        if "^" in xref_comp:
            return "^".join(list_to_comps(xref_comp.split("^")))
        return xref_comp.split(seperator)[1]
    def list_to_comps(lst):
        return list(set(map(xref_comp_to_function, filter(filter_comps, lst))))
    instance.diagnose()
    if seperator is None:
        return Diagnosis_Results(instance.diagnoses, instance.initial_tests, instance.error)
    diagnoses = []
    for diagnosis in instance.get_named_diagnoses():
        d = Diagnosis()
        d.diagnosis = list_to_comps(diagnosis.diagnosis)
        if len(d.diagnosis) == 0:
            continue
        d.probability = diagnosis.probability
        diagnoses.append(d)
    bugs = list_to_comps( Experiment_Data().get_named_bugs())
    return Diagnosis_Results(diagnoses, instance.initial_tests, instance.error, bugs=bugs)


def get_results_for_project(base_dir):
    cves = os.listdir(base_dir)
    full_results(base_dir, cves, results_file_name=os.path.join(base_dir, consts.RESULTS_FILE))
    check_fuzzing_influence(base_dir, cves, results_file_name=os.path.join(base_dir, consts.FUZZING_RESULTS_FILE))

if __name__=="__main__":
    # inst = readPlanningFile(r"C:\vulnerabilities\exported\CVE-2016-8866\fuzzing\xref_matrix.txt")
    # get_results_objects_for_instance(inst, "$")
    # inst.diagnose()
    # exit()
    base_dir = sys.argv[1]
    get_results_for_project(base_dir)
    exit() 
    check_fuzzing_influence(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2016-7531_Copy\fuzzing",
                            r"C:\vulnerabilities\ImageMagick_exploited\fuzzing_influence.csv")
    dirs = ["fuzzing5506", "fuzzing5508", "fuzzing5509", "fuzzing5510", "fuzzing5511", "fuzzing7531", "fuzzing7533",
     "fuzzing7535", "fuzzing7906", "fuzzing8866", "fuzzing9556"]
    full_results(["CVE-2016-7531", "CVE-2016-7533", "CVE-2016-8866", "CVE-2017-5506", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510",
                     "CVE-2017-5511"],
                      "dll_matrix.txt",
                      "entry_points_matrix.txt",
                      "function_matrix.txt",
                      "xref_matrix.txt",
                      r"C:\temp\full_results_done2.csv")
