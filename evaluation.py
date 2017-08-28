from sfl_diagnoser.Diagnoser.ExperimentInstance import ExperimentInstance
from sfl_diagnoser.Diagnoser.Experiment_Data import Experiment_Data
from sfl_diagnoser.Diagnoser.Diagnosis import Diagnosis
import sfl_diagnoser.Diagnoser.ExperimentInstance
from sfl_diagnoser.Diagnoser.diagnoserUtils import readPlanningFile, save_ds_to_matrix_file, write_merged_matrix
from sfl_diagnoser.Diagnoser.Diagnosis_Results import Diagnosis_Results
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
    components_indices = range(max(reduce(list.__add__, sfl_diagnoser.Diagnoser.ExperimentInstance.POOL.values())))
    components = list(set([xref_to_function(sfl_diagnoser.Diagnoser.ExperimentInstance.COMPONENTS_NAMES[x]) for x in
                           components_indices]))
    bugged_components = [xref_to_function(sfl_diagnoser.Diagnoser.ExperimentInstance.COMPONENTS_NAMES[b]) for b in sfl_diagnoser.Diagnoser.ExperimentInstance.BUGS]
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

def get_results_objects_for_instance(instance_file):
    base_instance = readPlanningFile(instance_file)
    optimized_matrix = tempfile.mktemp(prefix="optimized_")
    reduced_matrix = tempfile.mktemp(prefix="reduced_")
    merged_matrix = tempfile.mktemp(prefix="merged_")
    merged_reduced_matrix = tempfile.mktemp(prefix="merged_reduced_")

    save_ds_to_matrix_file(base_instance.initials_to_DS().optimize(), optimized_matrix)
    optimized_instance = readPlanningFile(optimized_matrix)
    optimized_instance.diagnose()
    optimized_results = Diagnosis_Results(optimized_instance.diagnoses, optimized_instance.initial_tests, optimized_instance.error)

    save_ds_to_matrix_file(optimized_instance.initials_to_DS().remove_duplicate_tests(), reduced_matrix)
    write_merged_matrix(optimized_instance, merged_matrix)
    reduced_instance = readPlanningFile(reduced_matrix)
    reduced_instance.diagnose()
    reduced_results = Diagnosis_Results(reduced_instance.diagnoses, reduced_instance.initial_tests, reduced_instance.error)

    merged_instance = readPlanningFile(merged_matrix)
    merged_instance.diagnose()
    merged_results = Diagnosis_Results(merged_instance.diagnoses, merged_instance.initial_tests, merged_instance.error)

    save_ds_to_matrix_file(merged_instance.initials_to_DS().remove_duplicate_tests(), merged_reduced_matrix)
    merged_reduced_instance = readPlanningFile(merged_reduced_matrix)
    merged_reduced_instance.diagnose()
    merged_reduced_results = Diagnosis_Results(merged_reduced_instance.diagnoses, merged_reduced_instance.initial_tests, merged_reduced_instance.error)
    return optimized_results, reduced_results, merged_results, merged_reduced_results


def full_results(cve_list, dll_matrix_file_name, function_matrix_file_name, xref_matrix_file_name, results_file_name):
    header = ["cve_number", "granularity", "matrix_type"]
    csv_lines = []
    added_results_header = False
    for cve in cve_list:
        fuzzing_dir = os.path.join(r"C:\vulnerabilities\ImageMagick_exploited", cve, "fuzzing")
        dll_matrix = os.path.join(fuzzing_dir, dll_matrix_file_name)
        function_matrix = os.path.join(fuzzing_dir, function_matrix_file_name)
        xref_matrix = os.path.join(fuzzing_dir, xref_matrix_file_name)
        for granularity, instance_file in zip(["dll", "function", "xref"], [dll_matrix, function_matrix, xref_matrix]):
            print cve, granularity
            base_results, reduced_results, merged_results, merged_reduced_results = get_results_objects_for_instance(instance_file)
            if not added_results_header:
                header += base_results.get_metrics_names()
                csv_lines.append(header)
                added_results_header = True
            csv_lines.append([cve, granularity, "base"] + base_results.get_metrics_values())
            csv_lines.append([cve, granularity, "remove_duplicate_tests"] + reduced_results.get_metrics_values())
            csv_lines.append([cve, granularity, "merge_same_comps"] + merged_results.get_metrics_values())
            csv_lines.append([cve, granularity, "remove_duplicate_tests&merge_same_comps"] + merged_reduced_results.get_metrics_values())
    with open(results_file_name, "wb") as f:
        writer = csv.writer(f)
        writer.writerows(csv_lines)


def check_fuzzing_for_dir(working_dir, results_file, number_files_to_read, matrix_path):
    results = []
    for number in number_files_to_read:
        diagnoser.campaign_matrix.create_matrix_for_dir(working_dir, results_file, matrix_path, number)
        base_results, reduced_results, merged_results, merged_reduced_results = get_results_objects_for_instance(matrix_path)
        results.append([number, base_results.precision, base_results.recall, base_results.wasted, base_results.num_comps, reduced_results.num_tests])
    return results

def check_fuzzing_influence(fuzzing_dir, results_file_name):
    number_files_to_read = [5] + range(50, 1001, 50)
    dll_matrix = tempfile.mktemp(dir=r"C:\temp", prefix= "dll")
    results = [["granularity", "num_fuzzed_files", "precision", "recall", "wasted", "#comps", "distinct_tests"]]
    results.extend(map(lambda result : ["dll"] + result, check_fuzzing_for_dir(os.path.join(fuzzing_dir, consts.DLL_WORKING_DIR),
                          os.path.join(fuzzing_dir,consts.DLL_DIAGNOSIS_RESULT), number_files_to_read, dll_matrix)))
    results.extend(map(lambda result : ["function"] + result, check_fuzzing_for_dir(os.path.join(fuzzing_dir, consts.FUNCTION_WORKING_DIR),
                          os.path.join(fuzzing_dir,consts.FUNCTION_DIAGNOSIS_RESULT), number_files_to_read, dll_matrix)))
    results.extend(map(lambda result : ["xref"] + result, check_fuzzing_for_dir(os.path.join(fuzzing_dir, consts.XREF_WORKING_DIR),
                          os.path.join(fuzzing_dir,consts.FUNCTION_DIAGNOSIS_RESULT), number_files_to_read, dll_matrix)))
    with open(results_file_name, "wb") as f:
        writer = csv.writer(f)
        writer.writerows(results)

def get_xref_diagnoses(instance, seperator="$"):
    def xref_comp_to_function(xref_comp):
        return xref_comp.split(seperator)[1]
    instance.diagnose()
    diagnoses = map(lambda diagnosis: map(xref_comp_to_function, diagnosis), instance.diagnoses)
    for diagnosis in diagnoses:
        diagnosis.diagnosis = list(set(diagnosis))
    return diagnoses

def get_xref_results(instance, seperator="$"):
    def xref_comp_to_function(xref_comp):
        return xref_comp.split(seperator)[1]

    instance.diagnose()
    diagnoses = []
    for diagnosis in diagnoses:
        d = Diagnosis()
        d.diagnosis = map(xref_to_function, diagnosis.diagnosis)
        d.probability = diagnosis.probability
    bugs = map(xref_comp_to_function, Experiment_Data().BUGS)
    return Diagnosis_Results(diagnoses, instance.initial_tests, instance.error, bugs=bugs)


if __name__=="__main__":
    check_fuzzing_influence(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2016-7531_Copy\fuzzing",
                            r"C:\vulnerabilities\ImageMagick_exploited\fuzzing_influence.csv")
    exit()
    full_results(["CVE-2016-7531", "CVE-2016-7533", "CVE-2016-8866", "CVE-2017-5506", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510",
                     "CVE-2017-5511"],
                      "dll_matrix.txt",
                      "function_matrix.txt",
                      "xref_matrix.txt",
                      r"C:\temp\full_results.csv")
