import os
import shutil
import glob

def clear_dir(dir_path):
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    return mkdir_if_not_exists(dir_path)

def mkdir_if_not_exists(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    return dir_path

def get_files_in_dir(dir_path):
    return glob.glob(os.path.join(dir_path, "*"))

def copy_files_to_dir(src, dst):
    mkdir_if_not_exists(dst)
    map(lambda f: shutil.copyfile(f, os.path.join(dst, os.path.basename(f))), get_files_in_dir(src))