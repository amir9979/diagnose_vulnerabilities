import os
import shutil
import glob

def mkdir_if_not_exists(dir_path):
    if not os.path.exists(dir_path):
        os.mkdir(dir_path)
    return dir_path

def get_files_in_dir(dir_path):
    return glob.glob(os.path.join(dir_path, "*"))

def copy_files_to_dir(src, dst):
    mkdir_if_not_exists(dst)
    map(lambda f: shutil.copyfile(f, os.path.join(dst, os.path.basename(f))), get_files_in_dir(src))

