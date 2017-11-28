import os
import utils
import subprocess
import shutil
import consts
import glob
from fuzzing_utils import fuzz_sedd_file

DEVENV = r"C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe"
BUILD = r'/build'
DEBUG = r'Debug|x86'
RELEASE = r'RELEASE'
CLEAN = r'/Clean'
UPGRADE = r"/Upgrade"
# CMAKE = r'cmake -E env CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -E env CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ADDITIONAL_LIBS="clang_rt.asan_dynamic-i386.lib" cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -E env CXXFLAGS="-fsanitize=address" ADDITIONAL_LIBS="clang_rt.asan_dynamic-i386.lib" cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -E env CMAKE_C_FLAGS ="-fsanitize=address" cmake -G "Visual Studio 14" -T LLVM-vs2014'
CMAKE = r'cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -G "Visual Studio 14"'
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
CDB_COMMAND = ".load msec;g;!exploitable -v;q"
EXPLOITABILITY_START = r"Exploitability Classification:"
NOT_AN_EXCEPTION = r"Exploitability Classification: NOT_AN_EXCEPTION"

# "C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" Boost.Hana.sln /p:Configuration=Debug /p:Platform=Win32 /v:m /m
# "C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe" RUN_TESTS.vcxproj /p:Configuration=Debug /p:Platform=Win32

class Reproducer(object):
    def __init__(self, exploits_dir, sources_dir, sln_path, git_path, bin_path, extended_path=None, dsw_path=None):
        self.exploits_dir = exploits_dir
        self.sources_dir = sources_dir
        self.sln_path = sln_path
        self.git_path = git_path
        self.bin_path = bin_path
        self.extended_path = extended_path
        self.dsw_path = dsw_path

    def copy_and_overwrite(self, src_path, dst_path):
        if os.path.exists(dst_path):
            shutil.rmtree(dst_path)
        # subprocess.Popen("XCOPY {src} {dst} /s /e".format(src=src_path,dst=dst_path))
        shutil.copytree(src_path, dst_path)

    def compile(self, base_dir):
        sln_path = os.path.join(base_dir, "vulnerable", self.sln_path)
        build_dir = os.path.dirname(sln_path)
        if not os.path.exists(build_dir):
            os.mkdir(build_dir)
        print build_dir
        if self.dsw_path:
            dsw_full_path = os.path.join(base_dir, "vulnerable", self.dsw_path)
            p = subprocess.Popen([DEVENV, dsw_full_path, UPGRADE],
                                 cwd=os.path.dirname(dsw_full_path), shell=True)  # , stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
            p.wait()
            pass
        p = subprocess.Popen(CMAKE, cwd=build_dir, shell=True)# , stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
        p.wait()
        self.edit_vcsproj_file(base_dir)
        clean_sln = [DEVENV, sln_path, CLEAN]
        print clean_sln
        p = subprocess.Popen(clean_sln, cwd=os.path.dirname(sln_path))
        p.wait()
        build_sln = [DEVENV, BUILD, RELEASE, sln_path]
        print build_sln
        p = subprocess.Popen(build_sln, cwd=os.path.dirname(sln_path))
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
                print "success", base_dir

    def create_dirs(self, base_dir, sources_dir):
        utils.mkdir_if_not_exists(base_dir)
        utils.mkdir_if_not_exists(os.path.join(base_dir, "exploit"))
        utils.mkdir_if_not_exists(os.path.join(base_dir, "vulnerable"))
        self.copy_and_overwrite(sources_dir, os.path.join(base_dir, "vulnerable", os.path.basename(sources_dir)))

    def edit_vcsproj_file(self, base_dir):
        vcsproj_to_edit = []
        for root, dirs, files in os.walk(os.path.join(base_dir, "vulnerable")):
            vcsproj_to_edit.extend(map(lambda name: os.path.join(root, name),
                                       filter(lambda name : name.endswith(".vcxproj"), files)))
        for vcsproj in vcsproj_to_edit:
            print vcsproj
            data = ""
            with open(vcsproj, "r") as f:
                data = f.read()
            with open(vcsproj, "wb") as f:
                f.write(data.replace("</AdditionalOptions>", " -fsanitize=address</AdditionalOptions>")
                        .replace("</AdditionalDependencies>", ' ;"C:\Temp\windows\clang_rt.asan_cxx-i386.lib";"C:\Temp\windows\clang_rt.asan_dynamic_runtime_thunk-i386.lib";"C:\Temp\windows\clang_rt.asan_dynamic-i386.lib";"C:\Temp\windows\clang_rt.asan-preinit-i386.lib";"C:\Temp\windows\clang_rt.builtins-i386.lib";"C:\Temp\windows\clang_rt.profile-i386.lib";"C:\Temp\windows\clang_rt.stats_client-i386.lib";"C:\Temp\windows\clang_rt.stats-i386.lib";"C:\Temp\windows\clang_rt.ubsan_standalone_cxx_dynamic-i386.lib";"C:\Temp\windows\clang_rt.ubsan_standalone_dynamic-i386.lib";"C:\include\GL\glut32.lib"</AdditionalDependencies><ImageHasSafeExceptionHandlers>false</ImageHasSafeExceptionHandlers>')
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\tiff.lib", r'"C:\Program Files (x86)\GnuWin32\lib\libtiff.lib"')
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\jpeg.lib", r'"C:\Program Files (x86)\GnuWin32\lib\jpeg.lib"')
                        .replace(r"</ClCompile>", "<AdditionalOptions>-fsanitize=address %(AdditionalOptions)</AdditionalOptions></ClCompile>")
                        .replace(r"<PlatformToolset>v140</PlatformToolset>", r"<PlatformToolset>LLVM-vs2014_xp</PlatformToolset>")
                        .replace(r"<AdditionalIncludeDirectories>", r"<AdditionalIncludeDirectories>C:\include;"))

    def fix_by_replace(self, base_dir, files_to_fix, text_to_replace, replace):
        for root, dirs, files in os.walk(os.path.join(base_dir, "vulnerable")):
            for file in files:
                for file_to_fix in files_to_fix:
                    if file_to_fix in file:
                        path = os.path.join(root, file)
                        data = ""
                        with open(path, "r") as f:
                            data = f.read()
                        with open(path, "wb") as f:
                            f.write(data.replace(text_to_replace.lower(), replace.lower()))

    def fix_int64_t(self, base_dir):
        self.fix_by_replace(base_dir, ["bsdtar.h"], "const char *tar_i64toa(int64_t);", " const char *tar_i64toa(long long);")

    def fix_uchar(self, base_dir):
        self.fix_by_replace(base_dir, ["jas_debug.c", "jas_icc.c", "jas_iccdata.c"], "uchar", "unsigned char")

    def fix_jas(self, base_dir):
        self.fix_by_replace(base_dir, ["jas_debug.c", "jas_icc.c", "jas_iccdata.c"], "jas_uchar", "unsigned char")
        self.fix_by_replace(base_dir, ["jas_icc.c"], "jas_ULONGLONG", "unsigned __int64")
        self.fix_by_replace(base_dir, ["jas_icc.c"], "jas_LONGLONG", "signed __int64")

    def fix_ulonglong(self, base_dir):
        self.fix_by_replace(base_dir, ["jas_icc.c"], "ULONGLONG", "unsigned __int64")

    def fix_longlong(self, base_dir):
        self.fix_by_replace(base_dir, ["jas_icc.c"], "LONGLONG", "signed __int64")

    def fix_setmod(self, base_dir):
        self.fix_by_replace(base_dir, ["read.c"], "_setmode(1, _O_BINARY);", "//_setmode(1, _O_BINARY);")

    def fix_io_h(self, base_dir):
        self.fix_by_replace(base_dir, ["jas_stream.c"], "#include <io.h>", "#include <io.h>\n#include <fcntl.h>")

    def fix_BCRYPT(self, base_dir):
        self.fix_by_replace(base_dir, ["archive_cryptor_private.h", "archive_cryptor.c", "archive_hmac.c"],
                            "defined(_WIN32) && !defined(__CYGWIN__) && defined(HAVE_BCRYPT_H)",
                            "defined(_WIN32) && !defined(__CYGWIN__) && defined(HAVE_BCRYPT_H) && FALSE")

    def fixes(self, base_dir):
        self.fix_int64_t(base_dir)
        self.fix_setmod(base_dir)
        self.fix_BCRYPT(base_dir)
        self.fix_jas(base_dir)
        self.fix_uchar(base_dir)
        self.fix_ulonglong(base_dir)
        self.fix_longlong(base_dir)
        self.fix_io_h(base_dir)


    def reproduce(self, cve_number, git_commit, exploit, bin_file_to_run, cmd_line="{PROGRAM} {SEEDFILE} NUL"):
        base_dir = os.path.join(self.exploits_dir, cve_number)
        self.create_dirs(base_dir, self.sources_dir)
        self.revert_to_commit(os.path.join(base_dir, r"vulnerable", self.git_path), git_commit)
        self.fixes(base_dir)
        self.compile(base_dir)
        exploit_path = self.save_exploit_file(base_dir, exploit)
        exploit_dir = os.path.dirname(exploit_path)
        new_env = os.environ.copy()
        if self.extended_path:
            new_env['PATH'] = new_env['PATH'] + ";" + os.path.join(base_dir, os.path.join(r"vulnerable",self.extended_path))
        # fuzz_sedd_file(exploit_path, exploit_dir, consts.FUZZ_ITERATIONS)
        for seedfile in glob.glob(os.path.join(exploit_dir, "*")):
            run_line = cmd_line.format(PROGRAM=self.get_bin_file_path(base_dir, bin_file_to_run),
                                       SEEDFILE=seedfile,
                                       TMP_FILE=r"C:\temp\tempfile")
            print run_line
            windbg_run = [CDB_EXE, "-amsec.dll", "-hd", "-xd", "gp", "-logo", self.get_log_file(base_dir), "-o", "-c",
                          CDB_COMMAND] + run_line.split()
            print windbg_run
            p = subprocess.Popen(windbg_run, env=new_env)
            p.wait()
            self.check_success(base_dir)

IMAGEMAGICK_DIR =r"C:\vulnerabilities\ImageMagick_exploited"
SOURCES =r"C:\vulnerabilities\ImageMagick_exploited\clean\ImageMagick-Windows"

class Upgrade_reproducer(Reproducer):

    def __init__(self, exploits_dir, sources_dir, sln_path, git_path, bin_path, dsw_path, extended_path=None):
        super(Upgrade_reproducer).__init__(exploits_dir, sources_dir, sln_path, git_path, bin_path, extended_path)
        self.dsw_path = dsw_path


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


def libarchive_reproduce2():
    libarchive_reproducer = Reproducer(r"C:\vulnerabilities\libarchive11",
                                         r"C:\vulnerabilities\libarchive\clean\libarchive",
                                         r"libarchive\libarchive.sln",
                                         r"libarchive",
                                         r"libarchive\bin\Release")
    libarchive_reproducer.reproduce("CVE-2015-8933", "3c7a6dc",
                                    r"C:\Users\User\Downloads\libarchive-undefined-signed-overflow.tar",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")

def libarchive_reproduce():
    libarchive_reproducer = Reproducer(r"C:\vulnerabilities\libarchive12",
                                       r"C:\vulnerabilities\libarchive\clean\libarchive",
                                       r"libarchive\libarchive.sln",
                                       r"libarchive",
                                       r"libarchive\bin\Release")
    libarchive_reproducer.reproduce("CVE-2015-8933", "3c7a6dc", r"C:\Users\User\Downloads\libarchive-undefined-signed-overflow.tar",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8689_2", "7f17c79", r"C:\Users\User\Downloads\118.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -f {SEEDFILE}")
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


def yara_reproduce():
    yara_reproducer = Reproducer(r"C:\vulnerabilities\yara",
                                       r"C:\vulnerabilities\yara\yara",
                                       r"yara\windows\vs2015\yara.sln",
                                       r"yara",
                                       r"yara\windows\vs2015\Debug")
    yara_reproducer.reproduce("CVE-2017-9465", "992480c", r"C:\Users\User\Downloads\yara_ir_yr_arena_write_data.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9465_1", "f0a98fb", r"C:\Users\User\Downloads\yara_ir_yr_arena_write_data.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9465_2", "a8f58d2", r"C:\Users\User\Downloads\yara_ir_yr_arena_write_data.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-9438", "58f72d4", r"C:\Users\User\Downloads\yara_so_yr_re_emit.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9438_1", "925bcf3", r"C:\Users\User\Downloads\yara_so_yr_re_emit.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9304", "10e8bd3", r"C:\Users\User\Downloads\yara_so_yr_re_emit2.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9304_1", "1aaac7b", r"C:\Users\User\Downloads\yara_so_yr_re_emit2.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-8929", "053e67e", r"C:\Users\User\Downloads\yara_uaf_sized_string_cmp.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-8929_1", "49fc70e", r"C:\Users\User\Downloads\yara_uaf_sized_string_cmp.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-8294", "4cab5b3", r"C:\Users\User\Downloads\yara_oobr_yr_re_exec.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-8294_1", "83d7998", r"C:\Users\User\Downloads\yara_oobr_yr_re_exec.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-8294_2", "d438c8a", r"C:\Users\User\Downloads\yara_oobr_yr_re_exec.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-5924", "7f02eca", r"C:\Users\User\Downloads\yara_uaf_yr_compiler_destroy.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-5923", "ab906da", r"C:\Users\User\Downloads\yara_hoobr_yyparse_l833.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2016-10211", "890c3f8", r"C:\Users\User\Downloads\yara_uaf.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2016-10210", "eb491e0", r"C:\Users\User\Downloads\yara_null_ptr.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\Users\User\Downloads\SysinternalsSuite\strings.exe")

def lepton_reproduce():
    lepton_reproducer = Reproducer(r"C:\vulnerabilities\lepton",
                                   r"C:\vulnerabilities\lepton\lepton",
                                   r"lepton\lepton.sln",
                                   r"lepton",
                                   r"lepton\Debug")
    lepton_reproducer.reproduce("CVE-2017-8891", "82167c1", r"C:\Users\User\Downloads\crash\id_000197,sig_11,src_001438+000435,op_splice,rep_8",
                              "lepton", "{PROGRAM} -unjailed  {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448", "7789d99", r"C:\Users\User\Downloads\sample (4)\0.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_1", "7789d99", r"C:\Users\User\Downloads\sample (4)\1.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_2", "7789d99", r"C:\Users\User\Downloads\sample (4)\2.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_3", "7789d99", r"C:\Users\User\Downloads\sample (4)\3.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_4", "7789d99", r"C:\Users\User\Downloads\sample (4)\4.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_5", "7789d99", r"C:\Users\User\Downloads\sample (4)\5.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    for ind, commit in enumerate(["91619e2cd62d89f0636eb0a3bc0f2836b20e6520", "fe97442aa30581271e09b5469bd46cfceec41414",
                                  "856e560b6854b02283ec17aa9abb424d4fde4505", "97a9b3c22117e990e16831a3edf75f295c1ee01a"]):
        lepton_reproducer.reproduce("try__" + str(ind),   commit, r"C:\Users\User\Downloads\lepton_testcases1\global_bof.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_1_" + str(ind),   commit, r"C:\Users\User\Downloads\lepton_testcases1\global_bof2.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_2_" + str(ind),   commit, r"C:\Users\User\Downloads\lepton_testcases1\global_bof3.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_3_" + str(ind),   commit, r"C:\Users\User\Downloads\lepton_testcases1\invalid_access.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_4_" + str(ind),   commit, r"C:\Users\User\Downloads\lepton_testcases1\unknown.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")


def openjpeg_reproduce():
    openjpeg_reproducer = Reproducer(r"C:\vulnerabilities\openjpeg4",
                                   r"C:\vulnerabilities\openjpeg\openjpeg",
                                   r"openjpeg\openjpeg.sln",
                                   r"openjpeg",
                                   r"openjpeg\bin\Release")
    openjpeg_reproducer.reproduce("CVE-2017-14041", "e528531", r"C:\Users\User\Downloads\00327-openjpeg-stackoverflow-pgxtoimage.pgx",
                                "opj_compress", "{PROGRAM} -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2k")
    # openjpeg_reproducer.reproduce("CVE-2017-14040", "2cd30c2", r"C:\Users\User\Downloads\00326-openjpeg-invalidwrite-tgatoimage.tga",
    #                             "opj_compress", "{PROGRAM} -r 20,10,1 -jpip -EPH -SOP -cinema2K 24 -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2k")
    # openjpeg_reproducer.reproduce("CVE-2017-14039", "c535531", r"C:\Users\User\Downloads\00322-openjpeg-heapoverflow-opj_t2_encode_packet",
    #                             "opj_compress", "{PROGRAM} -r 20,10,1 -jpip -EPH -SOP -cinema2K 24 -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2k")
    # openjpeg_reproducer.reproduce("CVE-2017-12982", "baf0c1a", r"C:\Users\User\Downloads\00315-openjpeg-memallocfailure-opj_aligned_alloc_n",
    #                             "opj_compress", "{PROGRAM} -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2c")
    # openjpeg_reproducer.reproduce("CVE-2016-9112", "d27ccf0", r"C:\Users\User\Downloads\poc_855",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.jp2")
    # openjpeg_reproducer.reproduce("CVE-2016-7445", "7c86204", r"C:\Users\User\Downloads\openjpeg-nullptr-github-issue-842.ppm",
    #                             "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.j2k")
    # openjpeg_reproducer.reproduce("CVE-2016-7445_1", "fac916f", r"C:\Users\User\Downloads\openjpeg-nullptr-github-issue-842.ppm",
    #                             "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.j2k")
    # openjpeg_reproducer.reproduce("CVE-2016-7163", "c16bc05", r"C:\Users\User\Downloads\poc.jp2",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-7163_1", "ef01f18", r"C:\Users\User\Downloads\poc.jp2",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-4796", "ef01f18", r"C:\Users\User\Downloads\poc.j2k",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-10507", "16b0e4a", r"C:\Users\User\Downloads\poc.bmp",
    #                             "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-10506", "d27ccf0", r"C:\Users\User\Downloads\issue731_2.j2k",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-10506_1", "d27ccf0", r"C:\Users\User\Downloads\issue731.j2k",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-10506_2", "d27ccf0", r"C:\Users\User\Downloads\poc (1).j2k",
    #                             "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2016-10504", "397f62c", r"C:\Users\User\Downloads\poc (1).bmp",
    #                             "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    # openjpeg_reproducer.reproduce("CVE-2015-8871", "940100c", r"C:\Users\User\Downloads\poc (1).bmp",
    #                             "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")

def jasper_reproduce():
    jasper_reproducer = Reproducer(r"C:\vulnerabilities\jasper_reproduce3",
                                       r"C:\vulnerabilities\clean\jasper",
                                       r"jasper\src\msvc\JasPer.sln",
                                       r"jasper",
                                       r"jasper\src\msvc\Win32_Release",
                                       dsw_path=r"jasper\src\msvc\jasper.dsw")
    jasper_reproducer.reproduce("CVE-2017-6850", "e96fc4f", r"C:\Users\User\Downloads\poc-master\poc-master\00124-jasper-nullptr-jp2_cdef_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_2", "a105443", r"C:\Users\User\Downloads\poc-master\poc-master\00124-jasper-nullptr-jp2_cdef_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_3", "607c263", r"C:\Users\User\Downloads\poc-master\poc-master\00124-jasper-nullptr-jp2_cdef_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_4", "9c88f65", r"C:\Users\User\Downloads\poc-master\poc-master\00124-jasper-nullptr-jp2_cdef_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_5", "562c0a7", r"C:\Users\User\Downloads\poc-master\poc-master\00124-jasper-nullptr-jp2_cdef_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")

    jasper_reproducer.reproduce("CVE-2016-9560", "1abc2e5", r"C:\Users\User\Downloads\poc-master\poc-master\00047-jasper-stackoverflow-jpc_tsfb_getbands2",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9557", "d42b238", r"C:\Users\User\Downloads\poc-master\poc-master\00020-jasper-signedintoverflow-jas_image_c",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9387", "d91198a", r"C:\Users\User\Downloads\poc-master\poc-master\00003-jasper-assert-jas_matrix_t",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9388", "411a406", r"C:\Users\User\Downloads\poc-master\poc-master\00005-jasper-assert-ras_getcmap",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9389", "dee11ec", r"C:\Users\User\Downloads\poc-master\poc-master\00006-jasper-assert-jpc_irct",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9389_1", "dee11ec", r"C:\Users\User\Downloads\poc-master\poc-master\00008-jasper-assert-jpc_iict",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9390", "ba2b9d0", r"C:\Users\User\Downloads\poc-master\poc-master\00007-jasper-assert-jas_matrix_t",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9391", "1e84674", r"C:\Users\User\Downloads\poc-master\poc-master\00014-jasper-assert-jpc_bitstream_getbits",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9392", "f703806", r"C:\Users\User\Downloads\poc-master\poc-master\00012-jasper-assert-calcstepsizes",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9393", "f703806", r"C:\Users\User\Downloads\poc-master\poc-master\00013-jasper-assert-jpc_pi_nextrpcl",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9394", "f703806", r"C:\Users\User\Downloads\poc-master\poc-master\00016-jasper-assert-jas_matrix_t",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9395", "d42b238", r"C:\Users\User\Downloads\poc-master\poc-master\00043-jasper-assert-jas_matrix_t",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-9262", "634ce8e", r"C:\Users\User\Downloads\poc-master\poc-master\00028-jasper-uaf-jas_realloc",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8887", "e24bdc7", r"C:\Users\User\Downloads\poc-master\poc-master\00002-jasper-NULLptr-jp2_colr_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8886", "6553664", r"C:\Users\User\Downloads\2.crashes (1)\2.crashes",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8885", "5d66894", r"C:\Users\User\Downloads\9.crash\9.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8885_1", "8f62b47", r"C:\Users\User\Downloads\9.crash\9.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8885_2", "8f62b47", r"C:\Users\User\Downloads\10.crash\10.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8885_3", "5d66894", r"C:\Users\User\Downloads\5.crashes\5.crashes",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8884", "5d66894", r"C:\Users\User\Downloads\5.crashes\5.crashes",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8883", "33cc2cf", r"C:\Users\User\Downloads\jasper-assert-jpc_dec_tiledecode\jasper-assert-jpc_dec_tiledecode.jp2",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8882", "69a1439", r"C:\Users\User\Downloads\jasper-nullptr-jpc_pi_destroy\jasper-nullptr-jpc_pi_destroy.jp2",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8693", "44a524e", r"C:\Users\User\Downloads\1.crash\1.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8693_1", "668e682", r"C:\Users\User\Downloads\1.crash\1.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8693_2", "668e682", r"C:\Users\User\Downloads\jasper-doublefree-mem_close\jasper-doublefree-mem_close.jpg",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8693_3", "44a524e", r"C:\Users\User\Downloads\jasper-doublefree-mem_close\jasper-doublefree-mem_close.jpg",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8692", "d8c2604", r"C:\Users\User\Downloads\11.crash\11.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8692_1", "d8c2604", r"C:\Users\User\Downloads\12.crash\12.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8691", "d8c2604", r"C:\Users\User\Downloads\12.crash\12.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8691_1", "d8c2604", r"C:\Users\User\Downloads\11.crash\11.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8690_1", "8f62b47", r"C:\Users\User\Downloads\9.crash\9.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8690_2", "8f62b47", r"C:\Users\User\Downloads\10.crash\10.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8690_3", "8f62b47", r"C:\Users\User\Downloads\11.crash\11.crash",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-8690", "5d66894", r"C:\Users\User\Downloads\5.crashes\5.crashes",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-10251", "1f0dfe5a", r"C:\Users\User\Downloads\poc-master\poc-master\00029-jasper-uninitvalue-jpc_pi_nextcprl",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-10250", "bdfe95a6e", r"C:\Users\User\Downloads\poc-master\poc-master\00002-jasper-NULLptr-jp2_colr_destroy",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2016-10249", "988f836", r"C:\Users\User\Downloads\poc-master\poc-master\00001-jasper-heapoverflow-jpc_dec_tiledecode",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")




def libtiff_reproduce():
    libtiff_reproducer = Reproducer(r"C:\vulnerabilities\libtiff_reproduce",
                                       r"C:\vulnerabilities\clean\libtiff",
                                       r"libtiff\tiff.sln",
                                       r"libtiff",
                                       r"libtiff\Release")
    libtiff_reproducer.reproduce("CVE-2015-8933", "3c7a6dc", r"C:\Users\User\Downloads\libarchive-undefined-signed-overflow.tar",
                                    "imginfo", "{PROGRAM} -f {SEEDFILE}")


if __name__ == "__main__":
    # yara_reproduce()
    # lepton_reproduce()
    # jasper_reproduce()
    # libtiff_reproduce()
    libarchive_reproduce()
    openjpeg_reproduce()

    # other_cve()
    # reproduce("CVE-0000-0000", "91cc3f3", r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5510\exploit\18.psb", "magick", "{PROGRAM} {SEEDFILE} NUL")