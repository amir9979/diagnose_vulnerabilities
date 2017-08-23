import os
import utils
import subprocess
import shutil

IMAGEMAGICK_DIR =r"C:\vulnerabilities\ImageMagick_exploited"
SOURCES =r"C:\vulnerabilities\ImageMagick_exploited\clean\ImageMagick-Windows"
DEVENV = r"C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe"
BUILD = r'/Build'
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
CDB_COMMAND = ".load msec;g;!exploitable -v;q"
EXPLOITABILITY_START = r"Exploitability Classification:"
NOT_AN_EXCEPTION = r"Exploitability Classification: NOT_AN_EXCEPTION"


def copy_and_overwrite(from_path, to_path):
    if os.path.exists(to_path):
        shutil.rmtree(to_path)
    shutil.copytree(from_path, to_path)

def compile(base_dir):
    sln_path = os.path.join(base_dir, r"vulnerable\ImageMagick-Windows\VisualMagick\VisualDynamicMT.sln")
    p = subprocess.Popen([DEVENV, sln_path, BUILD])
    p.wait()

def get_bin_file_path(base_dir, bin_name):
    return os.path.join(base_dir, r"vulnerable\ImageMagick-Windows\VisualMagick\bin\\{0}.exe".format(bin_name))

def create_dirs(base_dir, sources_dir=SOURCES):
    utils.mkdir_if_not_exists(base_dir)
    utils.mkdir_if_not_exists(os.path.join(base_dir, "exploit"))
    utils.mkdir_if_not_exists(os.path.join(base_dir, "vulnerable"))
    copy_and_overwrite(sources_dir, os.path.join(base_dir, "vulnerable", os.path.basename(sources_dir)))

def revert_to_commit(base_dir, git_commit):
    image_magick_path = os.path.join(base_dir, r"vulnerable\ImageMagick-Windows\ImageMagick")
    p = subprocess.Popen("git checkout {0}~1".format(git_commit).split(), cwd=image_magick_path)
    p.wait()

def save_exploit_file(base_dir, exploit):
    exploit_dir = os.path.join(base_dir, "exploit")
    exploit_path = os.path.join(exploit_dir, os.path.basename(exploit))
    shutil.copyfile(exploit, exploit_path)
    return exploit_path

def get_log_file(base_dir):
    return os.path.join(base_dir, "log.msec")

def check_success(base_dir):
    with open(get_log_file(base_dir)) as log:
        content = log.read()
        file_name = "failed"
        if EXPLOITABILITY_START in content and NOT_AN_EXCEPTION not in content:
            file_name = "success"
        with open(os.path.join(base_dir, file_name), "wb") as success:
            success.write(file_name)

def reproduce(cve_number, git_commit, exploit, bin_file_to_run, cmd_line="{PROGRAM} {SEEDFILE} NUL"):
    try:
        base_dir = os.path.join(IMAGEMAGICK_DIR, cve_number)
        create_dirs(base_dir)
        revert_to_commit(base_dir, git_commit)
        compile(base_dir)

        bin_path = get_bin_file_path(base_dir, bin_file_to_run)
        exploit_path = save_exploit_file(base_dir, exploit)
        run_line = cmd_line.format(PROGRAM=bin_path, SEEDFILE=exploit_path, TMP_FILE=r"C:\temp\tempfile")
        windbg_run = [CDB_EXE, "-amsec.dll", "-hd", "-xd", "gp", "-logo", get_log_file(base_dir), "-o", "-c", CDB_COMMAND] + run_line.split()
        print windbg_run
        p = subprocess.Popen(windbg_run)
        p.wait()
        check_success(base_dir)
    except Exception as e:
        print "failed", e

def new_cves():
    reproduce("CVE-2017-12418", "4638252", r"C:\Users\User\Downloads\Memory-Leak-1_output_fpx_1501588084.95",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.fpx")
    reproduce("CVE-2017-11750", "1828667", r"C:\Users\User\Downloads\SEGV-0x000000000000_output_aai_1501399328.45",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.aai")
    reproduce("CVE-2017-11755", "cb71321", r"C:\Users\User\Downloads\Memory-Leak-21_output_picon_1501391824.23",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.picon")
    reproduce("CVE-2017-11751", "cb71321", r"C:\Users\User\Downloads\Memory-Leak-13_output_picon_1501390784.98",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.picon")
    reproduce("CVE-2017-9501", "e057809", r"C:\Users\User\Downloads\assertion-failed-in-LockSemaphoreInfo-semaphore295",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    reproduce("CVE-2017-11531", "c81594c", r"C:\Users\User\Downloads\memory-leak_output_histogram_WriteHISTOGRAMImage",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.histogram")
    reproduce("CVE-2017-11531", "e793eb2", r"C:\Users\User\Downloads\Memory-Leak-19_output_msl_1501504023.36",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.msl")
    reproduce("CVE-2017-11523", "a8f9c2a", r"C:\Users\User\Downloads\cpu-ReadTXTImage.txt",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.bmp")
    reproduce("CVE-2017-UNKNNOW#621", "8dd3ac4", r"C:\Users\User\Downloads\bad_free_in_RelinquishMagickMemory",
              "identify", "{PROGRAM} {SEEDFILE} {TMP_FILE}.bmp")
    reproduce("CVE-2017-UNKNNOW#592", "9fd10cf", r"C:\Users\User\Downloads\sample (1).gif",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.gif")
    reproduce("CVE-2017-9499", "7fd4194", r"C:\Users\User\Downloads\assertion-failed-in-SetPixelChannelAttributes-pixel-accessor695 (1)",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")

def other_cve():
    reproduce("CVE-2017-12140", "9493314",
              r"C:\Users\User\Downloads\memory_exhaustion_in_ReadDCMImage",
              "identify", "{PROGRAM} {SEEDFILE}")
    reproduce("CVE-2017-11539", "36aad91", r"C:\Users\User\Downloads\memory-leak_output_art_ReadOnePNGImage",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.art")
    reproduce("CVE-2017-11533", "f0c29cc", r"C:\Users\User\Downloads\heap-buffer-overflow-READ-0x7fd806e82db2_output_uil_1500210468.72",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.uil")
    reproduce("CVE-2017-11753", "5095363", r"C:\Users\User\Downloads\heap-buffer-overflow-READ-0x0000006869f0_output_json_1501326140.06.fits",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.json")
    reproduce("CVE-2017-11753_V2", "ccc71c1", r"C:\Users\User\Downloads\heap-buffer-overflow-READ-0x0000006869f0_output_json_1501326140.06.fits",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.json")
    reproduce("CVE-2017-11310", "8ca3583", r"C:\Users\User\Downloads\read_user_chunk_callback.png",
              "identify ", "{PROGRAM} {SEEDFILE}")
    reproduce("CVE-2017-11446", "787ee25", r"C:\Users\User\Downloads\cpu-ReadPESImage",
              "identify", "{PROGRAM} {SEEDFILE}")
    reproduce("CVE-2017-11141", "cdafbc7", r"C:\Users\User\Downloads\ImageMagick-7.0.5-6-memory-exhaustion.MAT",
              "identify", "{PROGRAM} {SEEDFILE}")
    reproduce("CVE-2017-11535", "b8647f1", r"C:\Users\User\Downloads\heap-buffer-overflow-READ-0x7f58970bcdc4_output_ps_1500207243.43",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.ps")
    reproduce("CVE-2017-11537", "2bbc1b9", r"C:\Users\User\Downloads\FPE--0x7eff23c45e38_output_palm_1500208096.66",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.palm")
    reproduce("CVE-2017-11166", "31b842a", r"C:\Users\User\Downloads\ImageMagick-7.0.5-6-memory-exhaustion.XWD",
              "identify", "{PROGRAM} {SEEDFILE}")
    reproduce("CVE-2017-7606", "b218117", r"C:\Users\User\Downloads\00253-imagemagick-outsinde-unsigned-char (2)",
              "identify", "{PROGRAM} {SEEDFILE}")
    reproduce("CVE-2017-9500", "5d95b4c", r"C:\Users\User\Downloads\assertion-failed-in-ResetImageProfileIterator-profile1303_7.0.5-8_Q16",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    reproduce("CVE-2017-11170", "fbb5e1c", r"C:\Users\User\Downloads\ImageMagick-7.0.5-6-memory-exhaustion.VST",
              "identify", "{PROGRAM} {SEEDFILE}")


if __name__ == "__main__":
    other_cve()
    # reproduce("CVE-0000-0000", "91cc3f3", r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5510\exploit\18.psb", "magick", "{PROGRAM} {SEEDFILE} NUL")