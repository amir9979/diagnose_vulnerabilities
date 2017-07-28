import os
import glob
import FOE2.certfuzz.debuggers.msec
import tempfile
import sys
import shutil
import yaml

EXAMPLES_PATH = r"C:\vulnerabilities\ImageMagick_exploited\IM_examples"
DLL_INSTANCES_DIR = "dll_diagnosis"
DLL_WORKING_DIR = "dll_diagnosis_working_dir"

def get_images(path):
    return glob.glob(os.path.join(path, "*"))

def run_IM_on_images(program, images, working_dir, config, granularity, binary_to_diagnose):
    for image in images:
        cmdargs = config['target']['cmdline_template'].replace("$PROGRAM", program).replace("$SEEDFILE", image).split()
        debugger = FOE2.certfuzz.debuggers.msec.MsecDebugger(program=program,
                                  cmd_args=cmdargs,
                                  outfile_base=tempfile.mktemp(dir=working_dir, prefix=os.path.basename(image)),
                                  timeout=10,
                                  killprocname=None,
                                  exception_depth=1,
                                  workingdir=None,
                                  watchcpu=False,
                                  granularity=granularity,
                                  binary_to_diagnose=binary_to_diagnose)
        debugger.go()

def copy_examples_and_seedfiles(examples, fuzzing_dir):
    instances_dir = os.path.join(fuzzing_dir, DLL_INSTANCES_DIR)
    if not os.path.exists(instances_dir):
        shutil.copytree(examples, instances_dir)
        map(lambda f: shutil.copyfile(f, os.path.join(instances_dir, os.path.basename(f))), get_images(os.path.join(fuzzing_dir, "seedfiles")))
    return instances_dir



def run_examples_on_project(program, fuzzing_dir, granularity):
    instances_dir = copy_examples_and_seedfiles(EXAMPLES_PATH, fuzzing_dir)
    working_dir = os.path.join(fuzzing_dir, DLL_WORKING_DIR)
    if not os.path.exists(working_dir):
        os.mkdir(working_dir)
    else:
        shutil.rmtree(working_dir)
        os.mkdir(working_dir)
    config = yaml.load(open(os.path.join(fuzzing_dir, "config.yaml")))
    run_IM_on_images(program, get_images(instances_dir), working_dir, config, granularity, None)


if __name__ == "__main__":
    # run_examples_on_project(sys.argv[1], sys.argv[2])
    # exit()
    run_examples_on_project(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe",
                            r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing", None)
    exit()
    run_IM_on_images(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe",
                  get_images(EXAMPLES_PATH) +
                     [r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing\seedfiles\5.psd"],
                     r"C:\Temp\examples", None)
