import shutil
import scipy
import sys
import yaml
import diagnoser.campaign_matrix
import utils
from  FOE2.certfuzz.debuggers.msec import MsecDebugger
from FOE2.certfuzz.debuggers.tracing.ida.ida_consts import *
import consts
from fuzzing_utils import fuzz_project_dir, fuzz_seed_file
from tracingdata import TracingData
try:
    from SFL_diagnoser.Diagnoser.diagnoserUtils import readPlanningFile
except:
    from sfl_diagnoser.Diagnoser.diagnoserUtils import readPlanningFile
from sfl_diagnoser.Diagnoser.Diagnosis_Results import Diagnosis_Results


def run_debugger_on_files(program, files, working_dir, config, granularity, tracing_data):
    for input_file in files:
        if not os.path.isfile(input_file):
            pass
        cmdargs = config['target']['cmdline_template'].replace("$PROGRAM", program).replace("$SEEDFILE", input_file).split()
        extended_path = None
        if 'extended_path' in config['target']:
            extended_path = config['target']['extended_path']
        out_file = os.path.join(working_dir,os.path.basename(input_file))
        if os.path.exists(out_file):
            continue
        debugger = MsecDebugger(program=program,
                                cmd_args=cmdargs,
                                outfile_base=out_file,
                                timeout=60*4,
                                killprocname=None,
                                exception_depth=1,
                                workingdir=None,
                                watchcpu=False,
                                granularity=granularity,
                                binaries_to_diagnose=tracing_data.binaries_to_diagnose,
                                tracing_data=tracing_data.breakpoints_addrs,
                                extended_path=extended_path)
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
            pass #shutil.rmtree(path)
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

def get_binaries_to_diagnose(diagnosed_components, config):
    bin_dir = os.path.dirname(config['target']['program'])
    binaries_to_diagnose = []
    print "diagnosed_components", diagnosed_components
    for component in diagnosed_components:
        bin = os.path.join(bin_dir, component)
        if os.path.exists(component):
            binaries_to_diagnose.append(component)
        elif os.path.exists(bin):
            binaries_to_diagnose.append(bin)
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
    exploit_dir = os.path.join(fuzzing_dir, consts.EXPLOIT_DIR)
    utils.copy_files_to_dir(exploit_dir, seedfiles_dir)
    instances_dir = os.path.join(fuzzing_dir, consts.INSTANCES)
    config = yaml.load(open(os.path.join(fuzzing_dir, "config.yaml")))
    dll_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.DLL_WORKING_DIR))
    dll_matrix_file = os.path.join(fuzzing_dir, consts.DLL_MATRIX)
    function_matrix_file = os.path.join(fuzzing_dir, consts.FUNCTION_MATRIX)
    dominator_matrix_file = os.path.join(fuzzing_dir, consts.DOMINATOR_MATRIX)
    # entry_points_file = os.path.join(fuzzing_dir, consts.ENTRY_POINTS_MATRIX)
    utils.copy_files_to_dir(seedfiles_dir, instances_dir)
    utils.copy_files_to_dir(consts.EXAMPLES_DIR, instances_dir)
    fuzz_project_dir(seedfiles_dir, instances_dir, consts.FUZZ_ITERATIONS)

    # dll diagnoses
    run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), dll_working_dir, config, DLL_GRANULARITY,
                          None, None)
    diagnoser.campaign_matrix.create_matrix_for_dir(dll_working_dir, os.path.join(fuzzing_dir, consts.DLL_DIAGNOSIS_RESULT),
                                                    dll_matrix_file)
    dll_instance = readPlanningFile(dll_matrix_file)
    dll_instance.diagnose()
    # # #
    # # # # # entry points diagnoses
    # # # # named_diagnoses = filter(lambda diag: diag.probability > consts.DLL_DIAGNOSIS_THRESHOLD or True,
    # # # #                          dll_instance.get_named_diagnoses())
    # # # # entry_points_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.ENTRY_POINTS_WORKING_DIR))
    # # # # run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), entry_points_working_dir, config,
    # # # #                       ENTRY_POINTS_GRANULARITY,
    # # # #                       get_binaries_to_diagnose(named_diagnoses, config), None)
    # # # # diagnoser.campaign_matrix.create_matrix_for_dir(entry_points_working_dir,
    # # # #                                                 os.path.join(fuzzing_dir, consts.ENTRY_POINTS_DIAGNOSIS_RESULT),
    # # # #                                                 entry_points_file)
    # # # # entry_points_instance = readPlanningFile(entry_points_file)
    # # # # entry_points_instance.diagnose()
    # # #
    # # # # function diagnosis
    named_diagnoses = filter(lambda diag: diag.probability > consts.DLL_DIAGNOSIS_THRESHOLD,dll_instance.get_named_diagnoses())
    binaries_to_diagnose = get_binaries_to_diagnose(named_diagnoses, config)
    function_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.FUNCTION_WORKING_DIR))
    run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), function_working_dir, config, FUNCTION_GRANULARITY,
                          binaries_to_diagnose, None)
    diagnoser.campaign_matrix.create_matrix_for_dir(function_working_dir, os.path.join(fuzzing_dir,
                                                                                       consts.FUNCTION_DIAGNOSIS_RESULT),
                                                    function_matrix_file)

    function_instance = readPlanningFile(function_matrix_file)
    function_instance.diagnose()

    # dominators diagnosis
    diagnosed_components = filter(lambda x: '&' in x and "crt" not in x and "sub_" not in x and "asan" not in x
                                  ,map(lambda x: x[0], function_instance.get_components_probabilities_by_name()))
    tracing_data = {}
    for comp in diagnosed_components:
        dll = comp.split('#')[1]
        address = comp.split('&')[0]
        tracing_data.setdefault(dll, []).append(address)
    dominator_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.DOMINATOR_WORKING_DIR))
    run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), dominator_working_dir , config, DOMINATOR_GRANULARITY, binaries_to_diagnose, tracing_data)
    diagnoser.campaign_matrix.create_matrix_for_dir(dominator_working_dir, os.path.join(fuzzing_dir,
                                                                                   consts.FUNCTION_DIAGNOSIS_RESULT),
                                                    dominator_matrix_file)
    dominator_instance = readPlanningFile(dominator_matrix_file)
    dominator_instance.diagnose()

    # xref diagnosis
    diagnosed_components = map(lambda x: x[0],
                               filter(lambda x: '&' in x[0] and x[1] > 0.01,
                                      dominator_instance.get_components_probabilities_by_name()))
    diagnosed_components = map(lambda x: x[0], filter(lambda x: '&' in x[0],
                                  sorted(dominator_instance.get_components_probabilities_by_name(), key=lambda x: x[1],reverse=True))[:20])
    tracing_data = {}
    for comp in diagnosed_components:
        address, function_dll = comp.split('&')
        print function_dll
        tracing_data.setdefault(function_dll, []).extend(address.split("+"))
    xref_working_dir = utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.XREF_WORKING_DIR))
    run_debugger_on_files(program, utils.get_files_in_dir(instances_dir), xref_working_dir, config, XREF_GRANULARITY, binaries_to_diagnose, tracing_data)
    diagnoser.campaign_matrix.create_matrix_for_dir(xref_working_dir, os.path.join(fuzzing_dir,
                                                                                   consts.FUNCTION_DIAGNOSIS_RESULT),
                                                    os.path.join(fuzzing_dir, consts.XREF_MATRIX))

def get_binary_from_component_name(component_name):
    if '#' in component_name:
        return component_name.split('#')[1]
    return component_name

def generate_tracing_data(granularity, matrix_file=None):
    if matrix_file is None or not os.path.exists(matrix_file):
        return TracingData(granularity, None, None)
    sfl_matrix = readPlanningFile(matrix_file)
    sfl_matrix.diagnose()
    binaries_probabilities = map(lambda comp: (get_binary_from_component_name(comp[0]), comp[1]), sfl_matrix.get_components_probabilities_by_name())
    binaries = dict.fromkeys(set(map(lambda x: x[0], binaries_probabilities)), 0.0)
    for binary in binaries:
        binaries[binary] = sum(map(lambda comp: comp[1], filter(lambda comp: comp[0] == binary, binaries_probabilities)))
    named_diagnoses = filter(lambda binary: binaries[binary] > consts.DLL_DIAGNOSIS_THRESHOLD, binaries)
    binaries_to_diagnose = get_binaries_to_diagnose(named_diagnoses, config)
    breakpoints_addrs = None
    prev_instance = readPlanningFile(matrix_file)
    prev_instance.diagnose()
    if granularity == DOMINATOR_GRANULARITY:
        diagnosed_components = filter(lambda x: '&' in x and "crt" not in x and "sub_" not in x and "asan" not in x
                                      , map(lambda x: x[0], prev_instance.get_components_probabilities_by_name()))
        breakpoints_addrs = {}
        for comp in diagnosed_components:
            dll = comp.split('#')[1]
            address = comp.split('&')[0]
            breakpoints_addrs.setdefault(dll, []).append(address)
    elif granularity == XREF_GRANULARITY:
        diagnosed_components = map(lambda x: x[0], filter(lambda x: '&' in x[0],
                                                          sorted(
                                                              prev_instance.get_components_probabilities_by_name(),
                                                              key=lambda x: x[1], reverse=True))[:20])
        breakpoints_addrs = {}
        for comp in diagnosed_components:
            address, function_dll = comp.split('&')
            breakpoints_addrs.setdefault(function_dll, []).extend(address.split("+"))
    return TracingData(granularity, binaries_to_diagnose, breakpoints_addrs)

def diagnosis_by_fuzzing_entropy(program, fuzzing_dir, entropy_threshold, fuzzing_seed, fuzzed_files_per_iter=1, stop_iter=500):
    seedfiles_dir = os.path.join(fuzzing_dir, consts.SEEDFILES)
    matrix_file = None
    for granularity in [DLL_GRANULARITY, FUNCTION_GRANULARITY, DOMINATOR_GRANULARITY, XREF_GRANULARITY]:
        instances_dir = utils.clear_dir(os.path.join(fuzzing_dir, consts.INSTANCES, granularity, str(entropy_threshold), str(fuzzing_seed)))
        current_entropy = float('inf')
        previous_entropy = float('-inf')
        tracing_data = generate_tracing_data(granularity, matrix_file)
        matrix_file = os.path.join(fuzzing_dir, consts.FUZZING_MATRIX.format("{0}_{1}_{2}".format(granularity, str(entropy_threshold), str(fuzzing_seed))))
        if os.path.exists(matrix_file):
            os.remove(matrix_file)
        working_dir = utils.clear_dir(os.path.join(fuzzing_dir, consts.WORKING_DIR, granularity, str(entropy_threshold), str(fuzzing_seed)))
        diagnosis_result = os.path.join(fuzzing_dir,consts.DLL_DIAGNOSIS_RESULT if granularity == DLL_GRANULARITY else consts.FUNCTION_DIAGNOSIS_RESULT)
        for seed_example in utils.get_files_in_dir(seedfiles_dir):
            shutil.copy2(seed_example, instances_dir)
            instance_path = os.path.join(instances_dir, os.path.basename(seed_example))
            run_debugger_on_files(program, [instance_path], working_dir, config, granularity, tracing_data)
        iter_ind = 0
        while abs(current_entropy - previous_entropy) > entropy_threshold:
            fuzzed_files = fuzz_project_dir(seedfiles_dir, instances_dir, fuzzed_files_per_iter, fuzzing_seed)
            run_debugger_on_files(program, fuzzed_files, working_dir, config, granularity, tracing_data)
            diagnoser.campaign_matrix.create_matrix_for_dir(working_dir, diagnosis_result, matrix_file)
            sfl_matrix = readPlanningFile(matrix_file)
            sfl_matrix.diagnose()
            results = Diagnosis_Results(sfl_matrix.diagnoses, sfl_matrix.initial_tests, sfl_matrix.error)
            previous_entropy = current_entropy
            current_entropy = results.component_entropy
            iter_ind = iter_ind + 1
            if iter_ind > stop_iter:
                break


def various_fuzzing_experiments(program, fuzzing_dir):
    entropy_thresholds = [0.1, 0.2] + map(scipy.log10, range(1, 21)) # maximum entropy value of finite set S is |log S|
    fuzzing_seeds = [0.1, 0.2, 0.3]
    for entropy_threshold in entropy_thresholds:
        for fuzzing_seed in fuzzing_seeds:
            diagnosis_by_fuzzing_entropy(program, fuzzing_dir, entropy_threshold, fuzzing_seed)

if __name__ == "__main__":
    config = yaml.load(open(sys.argv[1]))
    program = config['target']['program']
    fuzzing_dir = os.path.dirname(config['directories']['results_dir'])
    various_fuzzing_experiments(program, fuzzing_dir)
    # program = sys.argv[1]
    # fuzzing_dir = sys.argv[2]
    # hierarchical_diagnosis(program, fuzzing_dir, True)
