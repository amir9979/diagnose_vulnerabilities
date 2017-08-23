import os
import glob

EXAMPALS_PATH = r"C:\vulnerabilities\ImageMagick_exploited\IM_examples"
CONVERT_PATH = r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5511\vulnerable\ImageMagick-Windows\VisualMagick\bin\convert.exe"
RUN_CMD = "{CONVERT} {SRC} {DST}"

def make_examples_of_type(extension):
    for file in glob.glob(os.path.join(EXAMPALS_PATH, "*")):
        cmd_format = RUN_CMD.format(CONVERT=CONVERT_PATH, TYPE=extension, SRC=file, DST=file.split(".")[0] + "." + extension)
        print cmd_format
        # os.system(cmd_format)

if __name__ == "__main__":
    make_examples_of_type("8BIM")