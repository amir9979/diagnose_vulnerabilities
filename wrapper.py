import sys
import basic_debuggers.run_examples
import diagnoser.campaign_matrix
import hierarchy.second_diagnosis
import os
import shutil
import yaml
from FOE2.certfuzz.debuggers.tracing.ida.ida_consts import DLL_GRANULARITY, FUNCTION_GRANULARITY

if __name__ == "__main__":
    program = sys.argv[1]
    fuzzing_dir = sys.argv[2]
    granularity = sys.argv[3]
    if granularity == DLL_GRANULARITY:
        basic_debuggers.run_examples.run_examples_on_project(program, fuzzing_dir, DLL_GRANULARITY)
        diagnoser.campaign_matrix.create_matrix_for_dir(os.path.join(fuzzing_dir, basic_debuggers.run_examples.DLL_WORKING_DIR),
                                                        os.path.join(fuzzing_dir, "bugged_dll.txt"),
                                                        os.path.join(fuzzing_dir,"dll_diagnosis.txt"))
    elif granularity == FUNCTION_GRANULARITY:
        fuzzed_dir = os.path.join(fuzzing_dir, hierarchy.second_diagnosis.FUZING_OUTPUT_DIR)
        if not os.path.exists(fuzzed_dir):
            os.mkdir(fuzzed_dir)
        else:
            shutil.rmtree(fuzzed_dir)
            os.mkdir(fuzzed_dir)
        fuzzed_working_dir = os.path.join(fuzzing_dir, hierarchy.second_diagnosis.FUZING_WORKING_DIR)
        if not os.path.exists(fuzzed_working_dir):
            os.mkdir(fuzzed_working_dir)
        hierarchy.second_diagnosis.fuzz_project_dir(fuzzing_dir)
        config = yaml.load(open(os.path.join(fuzzing_dir, "config.yaml")))
        binary_to_diagnose = os.path.join(os.path.dirname(config['target']['program']),
                     open(os.path.join(fuzzing_dir, "bugged_dll.txt")).read().replace("\n","").replace(" ",""))
        print binary_to_diagnose
        basic_debuggers.run_examples.run_IM_on_images(program,
                                                      basic_debuggers.run_examples.get_images(fuzzed_dir) +
                                                      basic_debuggers.run_examples.get_images(basic_debuggers.run_examples.EXAMPLES_PATH),
                                                      fuzzed_working_dir,
                                                      config, FUNCTION_GRANULARITY, binary_to_diagnose)
        diagnoser.campaign_matrix.create_matrix_for_dir(fuzzed_working_dir,
                                                        os.path.join(fuzzing_dir, "function_diagnosis.txt"),
                                                        os.path.join(fuzzing_dir, "function_diagnosis_matrix.txt"))

