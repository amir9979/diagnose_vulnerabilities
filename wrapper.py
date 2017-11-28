import shutil
import sys
import yaml
from sfl_diagnoser.Diagnoser.diagnoserUtils import readPlanningFile
import diagnoser.campaign_matrix
import utils
from  FOE2.certfuzz.debuggers.msec import MsecDebugger
from FOE2.certfuzz.debuggers.tracing.ida.ida_consts import *
import consts
import evaluation
from fuzzing_utils import fuzz_project_dir


def run_debugger_on_files(program, files, working_dir, config, granularity, binaries_to_diagnose, tracing_data):
    for input_file in files:
        if not os.path.isfile(input_file):
            pass
        cmdargs = config['target']['cmdline_template'].replace("$PROGRAM", program).replace("$SEEDFILE", input_file).split()
        out_file = os.path.join(working_dir,os.path.basename(input_file))
        if os.path.exists(out_file):
            continue
        debugger = MsecDebugger(program=program,
                                cmd_args=cmdargs,
                                outfile_base=out_file,
                                timeout=600,
                                killprocname=None,
                                exception_depth=1,
                                workingdir=None,
                                watchcpu=False,
                                granularity=granularity,
                                binaries_to_diagnose=binaries_to_diagnose,
                                tracing_data=tracing_data)
        debugger.go()

def copy_examples_and_seedfiles(examples, fuzzing_dir):
    instances_dir = os.path.join(fuzzing_dir, consts.DLL_INSTANCES_DIR)

    if not os.path.exists(instances_dir):
        shutil.copytree(examples, instances_dir)
        map(lambda f: shutil.copyfile(f, os.path.join(instances_dir, os.path.basename(f))), get_images(os.path.join(fuzzing_dir, "seedfiles")))
    return instances_dir

def run_and_diagnose(program, instances_dir, working_dir, diagnosis_result, diagnosis_matrix,
                     granularity, config, binaries_to_diagnose, tracing_data):
    run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), working_dir, config, granularity, binaries_to_diagnose, tracing_data)
    diagnoser.campaign_matrix.create_matrix_for_dir(working_dir, diagnosis_result, diagnosis_matrix)

def run_examples_on_project(program, fuzzing_dir, granularity):
    instances_dir = copy_examples_and_seedfiles(consts.EXAMPLES_DIR, fuzzing_dir)
    working_dir = os.path.join(fuzzing_dir, consts.DLL_WORKING_DIR)
    if not os.path.exists(working_dir):
        os.mkdir(working_dir)
    else:
        shutil.rmtree(working_dir)
        os.mkdir(working_dir)
    config = yaml.load(open(os.path.join(fuzzing_dir, "config.yaml")))
    run_debugger_on_files(program, get_images(instances_dir), working_dir, config, granularity, None, None)

def init_dirs(fuzzing_dir):
    for dir in [consts.INSTANCES, consts.DLL_WORKING_DIR, consts.ENTRY_POINTS_WORKING_DIR,
                consts.FUNCTION_WORKING_DIR, consts.XREF_WORKING_DIR]:
        path = os.path.join(fuzzing_dir, dir)
        if os.path.exists(path):
            shutil.rmtree(path)
        utils.mkdir_if_not_exists(path)

def get_diagnoses_by_sep(instance_diagnoses, seperator="$"):
    def filter_comps(xref_comp):
        return seperator in xref_comp
    def xref_comp_to_function(xref_comp):
        return xref_comp.split(seperator)[1]
    diagnoses_probabilities = {}
    for diagnosis in instance_diagnoses:
        comps = filter(filter_comps, diagnosis.diagnosis)
        if len(comps) > 0:
            diagnosis.diagnosis = sorted(list(set(map(xref_comp_to_function, comps))))
            key = str(diagnosis.diagnosis)
            if key in diagnoses_probabilities:
                diagnoses_probabilities[key].probability += diagnosis.probability
            else:
                diagnoses_probabilities[key] = diagnosis
    return diagnoses_probabilities.values()

def get_binaries_to_diagnose(diagnoses, config):
    diagnosed_components = reduce(list.__add__, [diagnosis.diagnosis for diagnosis in diagnoses], [])
    bin_dir = os.path.dirname(config['target']['program'])
    binaries_to_diagnose = []
    print "diagnosed_components", diagnosed_components
    for component in diagnosed_components:
        dll = os.path.join(bin_dir, component + ".dll")
        exe = os.path.join(bin_dir, component + ".exe")
        if os.path.exists(exe):
            binaries_to_diagnose.append(exe)
        elif os.path.exists(dll):
            binaries_to_diagnose.append(dll)
    return binaries_to_diagnose


def hierarchical_diagnosis(program, fuzzing_dir, is_continuous):
    """
    diagnose the program in few hierarchical steps:
    1) dll diagnoses
    1.1*) dll entry points diagnoses
    2) function diagnoses
    3) xref diagnoses
    :param program: program to diagnose
    :param fuzzing_dir: working dir
    :param is_continuous: whether to use known bugs or use the bugs from previous step
    :return:
    """
    init_dirs(fuzzing_dir)
    seedfiles_dir = os.path.join(fuzzing_dir, consts.SEEDFILES)
    instances_dir = os.path.join(fuzzing_dir, consts.INSTANCES)
    config = yaml.load(open(os.path.join(fuzzing_dir, "config.yaml")))
    dll_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.DLL_WORKING_DIR))
    dll_matrix_file = os.path.join(fuzzing_dir, consts.DLL_MATRIX)
    function_matrix_file = os.path.join(fuzzing_dir, consts.FUNCTION_MATRIX)
    entry_points_file = os.path.join(fuzzing_dir, consts.ENTRY_POINTS_MATRIX)
    utils.copy_files_to_dir(seedfiles_dir, instances_dir)
    # utils.copy_files_to_dir(consts.EXAMPLES_DIR, instances_dir)
    fuzz_project_dir(seedfiles_dir, instances_dir, consts.FUZZ_ITERATIONS)

    # dll diagnoses
    # run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), dll_working_dir, config, DLL_GRANULARITY,
    #                       None, None)
    # diagnoser.campaign_matrix.create_matrix_for_dir(dll_working_dir, os.path.join(fuzzing_dir, consts.DLL_DIAGNOSIS_RESULT),
    #                                                 dll_matrix_file)
    # dll_instance = readPlanningFile(dll_matrix_file)
    # dll_instance.diagnose()

    # entry points diagnoses
    # named_diagnoses = filter(lambda diag: diag.probability > consts.DLL_DIAGNOSIS_THRESHOLD or True,
    #                          dll_instance.get_named_diagnoses())
    # entry_points_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.ENTRY_POINTS_WORKING_DIR))
    # run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), entry_points_working_dir, config,
    #                       ENTRY_POINTS_GRANULARITY,
    #                       get_binaries_to_diagnose(named_diagnoses, config), None)
    # diagnoser.campaign_matrix.create_matrix_for_dir(entry_points_working_dir,
    #                                                 os.path.join(fuzzing_dir, consts.ENTRY_POINTS_DIAGNOSIS_RESULT),
    #                                                 entry_points_file)
    entry_points_instance = readPlanningFile(entry_points_file)
    entry_points_instance.diagnose()

    # function diagnosis
    named_diagnoses = filter(lambda diag: diag.probability > consts.DLL_DIAGNOSIS_THRESHOLD,
                             get_diagnoses_by_sep(entry_points_instance.get_named_diagnoses(),"#"))
    # function_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.FUNCTION_WORKING_DIR))
    binaries_to_diagnose = get_binaries_to_diagnose(named_diagnoses, config)
    # run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), function_working_dir, config, FUNCTION_GRANULARITY,
    #                       binaries_to_diagnose, None)
    # diagnoser.campaign_matrix.create_matrix_for_dir(function_working_dir, os.path.join(fuzzing_dir,
    #                                                                                    consts.FUNCTION_DIAGNOSIS_RESULT),
    #                                                 function_matrix_file)

    function_instance = readPlanningFile(function_matrix_file)
    function_instance.diagnose()

    # xref diagnosis
    diagnosed_components = filter(lambda x: '&' in x,
                                  map(lambda x: x[0], function_instance.get_components_probabilities_by_name()))
    tracing_data = {}
    for comp in diagnosed_components:
        dll = comp.split('#')[1]
        address = comp.split('&')[0]
        tracing_data.setdefault(dll, []).append(address)
    xref_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.XREF_WORKING_DIR))
    run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), xref_working_dir, config, XREF_GRANULARITY, binaries_to_diagnose, tracing_data)
    diagnoser.campaign_matrix.create_matrix_for_dir(xref_working_dir, os.path.join(fuzzing_dir,
                                                                                   consts.FUNCTION_DIAGNOSIS_RESULT),
                                                    os.path.join(fuzzing_dir, consts.XREF_MATRIX))



if __name__ == "__main__":
    program = sys.argv[1]
    fuzzing_dir = sys.argv[2]
    hierarchical_diagnosis(program, fuzzing_dir, True)
