import os
import utils
import subprocess
import shutil

DEVENV = r"C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe"
BUILD = r'/Build'
CLEAN = r'/Clean'
CMAKE = r"cmake ."
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
CDB_COMMAND = ".load msec;g;!exploitable -v;q"
EXPLOITABILITY_START = r"Exploitability Classification:"
NOT_AN_EXCEPTION = r"Exploitability Classification: NOT_AN_EXCEPTION"


class Reproducer(object):
    def __init__(self, exploits_dir, sources_dir, sln_path, git_path, bin_path):
        self.exploits_dir = exploits_dir
        self.sources_dir = sources_dir
        self.sln_path = sln_path
        self.git_path = git_path
        self.bin_path = bin_path

    def copy_and_overwrite(self, from_path, to_path):
        if os.path.exists(to_path):
            shutil.rmtree(to_path)
        shutil.copytree(from_path, to_path)

    def compile(self, sln_path):
        p = subprocess.Popen(CMAKE, cwd=os.path.dirname(sln_path))
        p.wait()
        clean_sln = [DEVENV, sln_path, CLEAN]
        print clean_sln
        p = subprocess.Popen(clean_sln)
        p.wait()
        build_sln = [DEVENV, sln_path, BUILD]
        print build_sln
        p = subprocess.Popen(build_sln)
        p.wait()

    def get_bin_file_path(self, base_dir, bin_name):
        return os.path.join(base_dir, os.path.join(r"vulnerable", self.bin_path, "{0}.exe".format(bin_name)))

    def revert_to_commit(self, git_path, git_commit):
        p = subprocess.Popen("git checkout -f {0}~1".format(git_commit).split(), cwd=git_path)
        p.wait()

    def save_exploit_file(self, base_dir, exploit):
        exploit_dir = os.path.join(base_dir, "exploit")
        exploit_path = os.path.join(exploit_dir, os.path.basename(exploit))
        shutil.copyfile(exploit, exploit_path)
        return exploit_path

    def get_log_file(self, base_dir):
        return os.path.join(base_dir, "log.msec")

    def check_success(self, base_dir):
        with open(self.get_log_file(base_dir)) as log:
            content = log.read()
            file_name = "failed"
            if EXPLOITABILITY_START in content and NOT_AN_EXCEPTION not in content:
                file_name = "success"
            with open(os.path.join(base_dir, file_name), "wb") as success:
                success.write(file_name)

    def create_dirs(self, base_dir, sources_dir):
        utils.mkdir_if_not_exists(base_dir)
        utils.mkdir_if_not_exists(os.path.join(base_dir, "exploit"))
        utils.mkdir_if_not_exists(os.path.join(base_dir, "vulnerable"))
        self.copy_and_overwrite(sources_dir, os.path.join(base_dir, "vulnerable", os.path.basename(sources_dir)))

    def reproduce(self, cve_number, git_commit, exploit, bin_file_to_run, cmd_line="{PROGRAM} {SEEDFILE} NUL"):
        try:
            base_dir = os.path.join(self.exploits_dir, cve_number)
            self.create_dirs(base_dir, self.sources_dir)
            self.revert_to_commit(os.path.join(base_dir, r"vulnerable", self.git_path), git_commit)
            self.compile(os.path.join(base_dir, "vulnerable", self.sln_path))

            run_line = cmd_line.format(PROGRAM=self.get_bin_file_path(base_dir, bin_file_to_run),
                                       SEEDFILE=self.save_exploit_file(base_dir, exploit),
                                       TMP_FILE=r"C:\temp\tempfile")
            print run_line
            windbg_run = [CDB_EXE, "-amsec.dll", "-hd", "-xd", "gp", "-logo", self.get_log_file(base_dir), "-o", "-c",
                          CDB_COMMAND] + run_line.split()
            print windbg_run
            p = subprocess.Popen(windbg_run)
            p.wait()
            self.check_success(base_dir)
        except Exception as e:
            print "failed", e

IMAGEMAGICK_DIR =r"C:\vulnerabilities\ImageMagick_exploited"
SOURCES =r"C:\vulnerabilities\ImageMagick_exploited\clean\ImageMagick-Windows"



def new_cves():
    image_magick_reproducer = Reproducer(r"C:\vulnerabilities\ImageMagick_exploited",
                                         r"C:\vulnerabilities\ImageMagick_exploited\clean\ImageMagick-Windows",
                                         r"ImageMagick-Windows\VisualMagick\VisualDynamicMT.sln",
                                         r"ImageMagick-Windows\ImageMagick",
                                         r"ImageMagick-Windows\VisualMagick\bin")
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


def libarchive_reproduce():
    libarchive_reproducer = Reproducer(r"C:\vulnerabilities\libarchive",
                                         r"C:\vulnerabilities\libarchive\clean\libarchive",
                                         r"libarchive\libarchive.sln",
                                         r"libarchive",
                                         r"libarchive\bin\Debug")
    libarchive_reproducer.reproduce("CVE-2015-8933", "3c7a6dc", r"C:\Users\User\Downloads\libarchive-undefined-signed-overflow.tar",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8689_2", "7f17c79", r"C:\Users\User\Downloads\118.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8688", "eec077f", r"C:\Users\User\Downloads\crash.bz2\crash.bz2",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("760", "eec077f", r"C:\Users\User\Downloads\113.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("62", "eec077f", r"C:\Users\User\Downloads\62.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("25", "eec077f", r"C:\Users\User\Downloads\25.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8687", "e37b620f", r"C:\Users\User\Downloads\9.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-7166", "6e06b1c89", r"C:\Users\User\Downloads\selfgz.gz",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-6250", "3014e198", r"C:\Users\User\Downloads\libarchiveOverflow.txt",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-5844", "3ad08e0", r"C:\Users\User\Downloads\libarchive-signed-int-overflow.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-5844_2", "e6c9668f", r"C:\Users\User\Downloads\libarchive-signed-int-overflow.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-5844_3", "e6c9668f", r"C:\Users\User\Downloads\libarchive-signed-int-overflow.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-4809", "fd7e0c0", r"C:\Users\User\Downloads\c014d4b4-1833-11e6-8ccf-b00bfbedb16c.png",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-4809_2", "fd7e0c0", r"C:\Users\User\Downloads\cc6569ea-1833-11e6-88fd-132060c69647.png",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-4809_3", "fd7e0c0", r"C:\Users\User\Downloads\d522f84a-1833-11e6-90cc-a1b97770bf9e.png",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10350", "88eb9e1", r"C:\Users\User\Downloads\00106-libarchive-heapoverflow-archive_read_format_cab_read_header",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10349", "88eb9e1", r"C:\Users\User\Downloads\00105-libarchive-heapoverflow-archive_le32dec",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10209", "42a3408", r"C:\Users\User\Downloads\la_segv_archive_wstring_append_from_mbs",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10209_2", "e8a9de5", r"C:\Users\User\Downloads\la_segv_archive_wstring_append_from_mbs",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8934", "603454e", r"C:\Users\User\Downloads\bsdtar-invalid-read.rar",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8932", "f0b1dbb", r"C:\Users\User\Downloads\libarchive-undefined-shiftleft",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8930", "01cfbca", r"C:\Users\User\Downloads\hang.iso",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8930_2", "39fc593", r"C:\Users\User\Downloads\hang.iso",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8928", "64d5628", r"C:\Users\User\Downloads\libarchive-oob-process_add_entry.mtree",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8927", "eff35d4", r"C:\Users\User\Downloads\pwcrash.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8926", "aab7393", r"C:\Users\User\Downloads\segfault.rar",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8925", "1e18cbb71515a22b2a6f1eb4aaadea461929b834", r"C:\Users\User\Downloads\read_mtree.mtree",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8924", "bb9b157", r"C:\Users\User\Downloads\tar-heap-overflow.tar",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8923", "9e0689c", r"C:\Users\User\Downloads\bsdtar-zip-crash-variant1.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8923_2", "9e0689c", r"C:\Users\User\Downloads\bsdtar-zip-crash-variant2.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8923_3", "9e0689c", r"C:\Users\User\Downloads\bsdtar-zip-crash-variant3.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8922", "d094dc", r"C:\Users\User\Downloads\bsdtar-null-ptr.7z",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8921", "1cbc76f", r"C:\Users\User\Downloads\invalid-read-overflow.mtree",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8920", "97f964e", r"C:\Users\User\Downloads\bsdtar-invalid-read-stack.a",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8919", "e8a2e4d", r"C:\Users\User\Downloads\bsdtar-invalid-read.lzh",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8918", "b6ba560", r"C:\Users\User\Downloads\memcpy.cab",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8915", "24f5de6", r"C:\Users\User\Downloads\crash.cpio",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")




if __name__ == "__main__":
    libarchive_reproduce()

    # other_cve()
    # reproduce("CVE-0000-0000", "91cc3f3", r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5510\exploit\18.psb", "magick", "{PROGRAM} {SEEDFILE} NUL")