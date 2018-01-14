import os
import csv
import utils
import subprocess
import shutil
import yaml
import consts
import glob
from fuzzing_utils import fuzz_sedd_file

DEVENV = r"C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe"
# DEVENV = r"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"
BASE_CONFIG = r"C:\vulnerabilities\config.yaml"
BUILD = r'/build'
DEBUG = r'Debug|x86'
RELEASE = r'RELEASE'
CLEAN = r'/Clean'
UPGRADE = r"/Upgrade"
# CMAKE = r'cmake -E env CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -E env CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ADDITIONAL_LIBS="clang_rt.asan_dynamic-i386.lib" cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -E env CXXFLAGS="-fsanitize=address" ADDITIONAL_LIBS="clang_rt.asan_dynamic-i386.lib" cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -E env CMAKE_C_FLAGS ="-fsanitize=address" cmake -G "Visual Studio 14" -T LLVM-vs2014'
CMAKE = r'cmake .. -G "Visual Studio 14" -T LLVM-vs2014'
CMAKE = r'cmake -G "Visual Studio 14" -T LLVM-vs2014'
# CMAKE = r'cmake -DENABLE_ZLIB=OFF -DBUILD_wireshark_gtk=ON -G "Visual Studio 14"'
# CMAKE = r'cmake -DENABLE_ZLIB=OFF -DBUILD_wireshark_gtk=ON'
# CMAKE = r'cmake .. -G "Visual Studio 14"'
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
CDB_EXE = r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x86\cdb.exe"
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
            for path in [self.dsw_path, self.sln_path]:
                path_to_update = os.path.join(base_dir, "vulnerable", path)
                p = subprocess.Popen([DEVENV, path_to_update, UPGRADE],
                                     cwd=os.path.dirname(path_to_update), shell=True)  # , stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
                p.wait()
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
            if file_name == "success":
                return True
            else:
                return False

    def create_dirs(self, base_dir, sources_dir):
        utils.mkdir_if_not_exists(base_dir)
        utils.mkdir_if_not_exists(os.path.join(base_dir, "exploit"))
        utils.mkdir_if_not_exists(os.path.join(base_dir, "vulnerable"))
        utils.mkdir_if_not_exists(os.path.join(base_dir, "fuzzing"))
        self.copy_and_overwrite(sources_dir, os.path.join(base_dir, "vulnerable", os.path.basename(sources_dir)))

    def create_config(self, base_dir, cmd_line, program):
        config = yaml.load(open(BASE_CONFIG))
        config['target']['cmdline_template'] = cmd_line.format(PROGRAM=r"$PROGRAM", SEEDFILE=r"$SEEDFILE",
                                                               TMP_FILE=r"C:\temp\tempfile")
        config['target']['program'] = program
        fuzzing_dir = os.path.join(base_dir, "fuzzing")
        utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.SEEDFILES))
        utils.mkdir_if_not_exists(os.path.join(fuzzing_dir, consts.INSTANCES))
        utils.copy_files_to_dir(os.path.join(base_dir, "exploit"), os.path.join(fuzzing_dir, consts.SEEDFILES))
        config['directories']['seedfile_dir'] = os.path.join(fuzzing_dir, consts.SEEDFILES)
        config['directories']['working_dir'] = os.path.join(fuzzing_dir, "working_dir")
        config['directories']['results_dir'] = os.path.join(fuzzing_dir, "results")
        with open(os.path.join(fuzzing_dir, r"config.yaml"), "wb") as f:
            f.write(yaml.dump(config))

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
                        .replace(r"<Optimization>MaxSpeed</Optimization>",r"<Optimization>Disabled</Optimization>")
                        .replace(r"jansson.lib",r"C:\include\jansson.lib")
                        .replace(r"libcrypto.lib",r"C:\OpenSSL-Win32\lib\libcrypto.lib")
                        .replace("</AdditionalDependencies>", ' ;"C:\Temp\windows\clang_rt.asan_cxx-i386.lib";"C:\Temp\windows\clang_rt.asan_dynamic_runtime_thunk-i386.lib";"C:\Temp\windows\clang_rt.asan_dynamic-i386.lib";"C:\Temp\windows\clang_rt.asan-preinit-i386.lib";"C:\Temp\windows\clang_rt.builtins-i386.lib";"C:\Temp\windows\clang_rt.profile-i386.lib";"C:\Temp\windows\clang_rt.stats_client-i386.lib";"C:\Temp\windows\clang_rt.stats-i386.lib";"C:\Temp\windows\clang_rt.ubsan_standalone_cxx_dynamic-i386.lib";"C:\Temp\windows\clang_rt.ubsan_standalone_dynamic-i386.lib";"C:\include\GL\glut32.lib";"Bcrypt.lib";"C:\include\jansson.lib";"C:\OpenSSL-Win32\lib\libcrypto.lib";"C:\OpenSSL-Win32\lib\libssl.lib";"C:\OpenSSL-Win32\lib\openssl.lib"</AdditionalDependencies><ImageHasSafeExceptionHandlers>false</ImageHasSafeExceptionHandlers>')
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\tiff.lib", r'"C:\Program Files (x86)\GnuWin32\lib\libtiff.lib"')
                        .replace(r"C:\Users\amirelm\AppData\Local\Continuum\anaconda2\Library\lib\tiff.lib", r'"C:\Program Files (x86)\GnuWin32\lib\libtiff.lib"')
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\jpeg.lib", r'"C:\Program Files (x86)\GnuWin32\lib\jpeg.lib"')
                        .replace(r"C:\Program Files (x86)\GnuWin32\lib\libjpeg.lib", r'"C:\Program Files (x86)\GnuWin32\lib\jpeg.lib"')
                        .replace(r"C:\Users\amirelm\AppData\Local\Continuum\anaconda2\Library\lib\jpeg.lib", r'"C:\Program Files (x86)\GnuWin32\lib\jpeg.lib"')
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5PrintSupport.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5PrintSupport.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5Multimedia.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5Multimedia.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5Svg.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5Svg.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5WinExtras.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5WinExtras.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5Network.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5Network.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5Widgets.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5Widgets.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5Gui.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5Gui.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\Qt5Core.lib", r"C:\Qt2\5.10.0\msvc2015\lib\Qt5Core.lib")
                        .replace(r"C:\Users\User\Anaconda2\Library\lib\qtmain.lib", r"C:\Qt2\5.10.0\msvc2015\lib\qtmain.lib")
                        .replace(r"C:\Users\amirelm\AppData\Local\Continuum\anaconda2\Library\lib\bzip2.lib", r"C:\Program Files (x86)\GnuWin32\lib\bzip2.lib")
                        .replace(r"</ClCompile>", "<AdditionalOptions>-fsanitize=address %(AdditionalOptions)</AdditionalOptions></ClCompile>")
                        .replace(r"<PlatformToolset>v140</PlatformToolset>", r"<PlatformToolset>LLVM-vs2014_xp</PlatformToolset>")
                        .replace(r"<GenerateDebugInformation>false</GenerateDebugInformation>", r"<GenerateDebugInformation>true</GenerateDebugInformation>")
                        .replace(r"</Link>", r"<FullProgramDatabaseFile>true</FullProgramDatabaseFile></Link>")
                        .replace(r"<AdditionalIncludeDirectories>", r"<AdditionalIncludeDirectories>C:\include;")
                        .replace(r"..\..\libpng\Release\libpng.lib",r"C:\Program Files (x86)\GnuWin32\lib\libpng.lib")
                        .replace(r"..\..\zlib\Release\zlib.lib",r"C:\Program Files (x86)\GnuWin32\lib\zlib.lib")
                        .replace(r"..\..\jpeg\Release\libjpeg.lib",r"C:\Program Files (x86)\GnuWin32\lib\libjpeg.lib")
                        .replace(r"..\..\libwebp\Release\libwebp.lib",r"C:\include\webp\libwebp.lib")
                        .replace(r"<RuntimeLibrary>MultiThreaded</RuntimeLibrary>",r"<RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>")
                        .replace(r"!Exists('..\packages\yara-vs2015-binary-dependencies.0.0.1\build\native\yara-vs2015-binary-dependencies.targets')",
                                 r"Exists('..\packages\yara-vs2015-binary-dependencies.0.0.1\build\native\yara-vs2015-binary-dependencies.targets')"))

    def fix_by_replace(self, base_dir, files_to_fix, text_to_replace, replace):
        for root, dirs, files in os.walk(os.path.join(base_dir, "vulnerable")):
                for file_to_fix in files_to_fix:
                    if file_to_fix in files:
                        path = os.path.join(root, file_to_fix)
                        data = ""
                        with open(path, "r") as f:
                            data = f.read()
                        with open(path, "wb") as f:
                            data = data.replace(text_to_replace, replace)
                            if text_to_replace != text_to_replace.lower():
                                data = data.replace(text_to_replace.lower(), replace.lower())
                            f.write(data)

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

    def fix_open_flags(self, base_dir):
        self.fix_by_replace(base_dir, ["concat.cc"], "O_BINARY", "0x8000")
        self.fix_by_replace(base_dir, ["concat.cc"], "O_RDONLY", "0x0000")

    def fix_const(self, base_dir):
        self.fix_by_replace(base_dir, ["jas_image.h"], 'jas_image_t *jpg_decode(jas_stream_t *in, const char *optstr);', 'jas_image_t *jpg_decode(jas_stream_t *in, char *optstr);')
        self.fix_by_replace(base_dir, ["jas_image.h"], 'int jpg_encode(jas_image_t *image, jas_stream_t *out, const char *optstr);', 'int jpg_encode(jas_image_t *image, jas_stream_t *out, char *optstr);')
        self.fix_by_replace(base_dir, ["jpg_enc.c"], 'int jpg_encode(jas_image_t *image, jas_stream_t *out, const char *optstr)', 'int jpg_encode(jas_image_t *image, jas_stream_t *out, char *optstr)')
        self.fix_by_replace(base_dir, ["jpg_dec.c"], 'jas_image_t *jpg_decode(jas_stream_t *in, const char *optstr)', 'jas_image_t *jpg_decode(jas_stream_t *in, char *optstr)')

    def fix_config_include(self, base_dir):
        self.fix_by_replace(base_dir, ["mem.h", "endian.h", "strutils.h"], '#include "config.h"', '#include "..\..\..\windows\include\config.h"')
        self.fix_by_replace(base_dir, ["mem.h", "endian.h", "strutils.h"], '#include <config.h>', '#include "..\..\..\windows\include\config.h"')
        self.fix_by_replace(base_dir, ["yara.c", "yarac.c"], '#include "config.h"', '#include "windows\include\config.h"')
        self.fix_by_replace(base_dir, ["yara.c", "yarac.c"], '#include <config.h>', '#include "windows\include\config.h"')
        self.fix_by_replace(base_dir, ["modules.c", "dotnet.c", "pe.c", "strutils.c", "test-pe.c"], '#include <config.h>', '#include "..\windows\include\config.h"')
        self.fix_by_replace(base_dir, ["modules.c", "dotnet.c", "pe.c", "strutils.c", "test-pe.c"], '#include "config.h"', '#include "..\windows\include\config.h"')

    def fix_BCRYPT(self, base_dir):
        self.fix_by_replace(base_dir, ["archive_cryptor_private.h", "archive_cryptor.c", "archive_hmac.c"],
                            "defined(_WIN32) && !defined(__CYGWIN__) && defined(HAVE_BCRYPT_H)",
                            "defined(_WIN32) && !defined(__CYGWIN__) && defined(HAVE_BCRYPT_H) && FALSE")

    def fix_imagemagick(self, base_dir):
        self.fix_by_replace(base_dir, ["jpeglib.h"], "UINT16", "unsigned short")
        self.fix_by_replace(base_dir, ["jpeglib.h"], "UINT8", "unsigned char")

    def fix_sll(self, base_dir):
        self.fix_by_replace(base_dir, ["archive_cryptor_private.h", "archive_cryptor.c", "archive_hmac_private.h", "archive_hmac.c"],
                            "#elif defined(HAVE_LIBCRYPTO)", "#elif defined(HAVE_LIBCRYPTO) && FALSE")

    def fix_int64(self, base_dir):
        self.fix_by_replace(base_dir, ["tiffcp.c", "tiffsplit.c"],
                            "uint64", "int64")
        self.fix_by_replace(base_dir, ["tiffcp.c", "tiffsplit.c"],
                            "int64", "__int64")
        self.fix_by_replace(base_dir, ["tiffsplit.c"],
                            "tmsize_t", "size_t")
        self.fix_by_replace(base_dir, ["tiffcp.c"],
                            "TIFFTAG_LZMAPRESET", "65562")
        self.fix_by_replace(base_dir, ["tiffcp.c"],
                            "COMPRESSION_LZMA", "34925")

    def fixes(self, base_dir):
        self.fix_int64_t(base_dir)
        self.fix_setmod(base_dir)
        self.fix_BCRYPT(base_dir)
        self.fix_jas(base_dir)
        self.fix_uchar(base_dir)
        self.fix_ulonglong(base_dir)
        self.fix_longlong(base_dir)
        self.fix_io_h(base_dir)
        self.fix_open_flags(base_dir)
        self.fix_config_include(base_dir)
        self.fix_const(base_dir)
        self.fix_imagemagick(base_dir)
        self.fix_sll(base_dir)
        self.fix_int64(base_dir)


    def reproduce(self, cve_number, git_commit, exploit, bin_file_to_run, cmd_line="{PROGRAM} {SEEDFILE} NUL"):
        base_dir = os.path.join(self.exploits_dir, cve_number)
        self.create_dirs(base_dir, self.sources_dir)
        self.revert_to_commit(os.path.join(base_dir, r"vulnerable", self.git_path), git_commit)
        self.fixes(base_dir)
        self.compile(base_dir)
        program = self.get_bin_file_path(base_dir, bin_file_to_run)
        self.create_config(base_dir, cmd_line, program)
        exploit_path = self.save_exploit_file(base_dir, exploit)
        exploit_dir = os.path.dirname(exploit_path)
        new_env = os.environ.copy()
        if self.extended_path:
            new_env['PATH'] = os.path.join(base_dir, os.path.join(r"vulnerable",self.extended_path)) + ";" + new_env['PATH']
        # fuzz_sedd_file(exploit_path, exploit_dir, consts.FUZZ_ITERATIONS)
        for seedfile in glob.glob(os.path.join(exploit_dir, "*")):
            run_line = cmd_line.format(PROGRAM=program,
                                       SEEDFILE=seedfile,
                                       TMP_FILE=r"C:\temp\tempfile")
            windbg_run = [CDB_EXE, "-amsec.dll", "-hd", "-xd", "gp", "-logo", self.get_log_file(base_dir), "-o", "-c",
                          CDB_COMMAND] + run_line.split()
            p = subprocess.Popen(windbg_run, env=new_env)
            p.wait()
            if self.check_success(base_dir):
                print "start python.exe wrapper.py", program, os.path.join(base_dir, "fuzzing")

IMAGEMAGICK_DIR =r"C:\vulnerabilities\ImageMagick_exploited"
SOURCES =r"C:\vulnerabilities\ImageMagick_exploited\clean\ImageMagick-Windows"


def image_magick_reproduce():
    image_magick_reproducer = Reproducer(r"C:\vulnerabilities\ImageMagick_reproduce",
                                         r"C:\vulnerabilities\ImageMagick_exploited\clean\ImageMagick-Windows",
                                         r"ImageMagick-Windows\VisualMagick\VisualDynamicMT.sln",
                                         r"ImageMagick-Windows\ImageMagick",
                                         r"ImageMagick-Windows\VisualMagick\bin")
    image_magick_reproducer.reproduce("CVE-2017-12418", "4638252", r"C:\vulnerabilities\attachments\Memory-Leak-1_output_fpx_1501588084.95",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.fpx")
    image_magick_reproducer.reproduce("CVE-2017-11750", "1828667", r"C:\vulnerabilities\attachments\SEGV-0x000000000000_output_aai_1501399328.45",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.aai")
    image_magick_reproducer.reproduce("CVE-2017-11755", "cb71321", r"C:\vulnerabilities\attachments\Memory-Leak-21_output_picon_1501391824.23",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.picon")
    image_magick_reproducer.reproduce("CVE-2017-11751", "cb71321", r"C:\vulnerabilities\attachments\Memory-Leak-13_output_picon_1501390784.98",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.picon")
    image_magick_reproducer.reproduce("CVE-2017-9501", "e057809", r"C:\vulnerabilities\attachments\assertion-failed-in-LockSemaphoreInfo-semaphore295",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    image_magick_reproducer.reproduce("CVE-2017-11531", "c81594c", r"C:\vulnerabilities\attachments\memory-leak_output_histogram_WriteHISTOGRAMImage",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.histogram")
    image_magick_reproducer.reproduce("CVE-2017-11531", "e793eb2", r"C:\vulnerabilities\attachments\Memory-Leak-19_output_msl_1501504023.36",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.msl")
    image_magick_reproducer.reproduce("CVE-2017-11523", "a8f9c2a", r"C:\vulnerabilities\attachments\cpu-ReadTXTImage.txt",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.bmp")
    image_magick_reproducer.reproduce("CVE-2017-UNKNNOW#621", "8dd3ac4", r"C:\vulnerabilities\attachments\bad_free_in_RelinquishMagickMemory",
              "identify", "{PROGRAM} {SEEDFILE} {TMP_FILE}.bmp")
    image_magick_reproducer.reproduce("CVE-2017-UNKNNOW#592", "9fd10cf", r"C:\vulnerabilities\attachments\sample (1).gif",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.gif")
    image_magick_reproducer.reproduce("CVE-2017-9499", "7fd4194", r"C:\vulnerabilities\attachments\assertion-failed-in-SetPixelChannelAttributes-pixel-accessor695 (1)",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    image_magick_reproducer.reproduce("CVE-2017-12140", "9493314",
              r"C:\vulnerabilities\attachments\memory_exhaustion_in_ReadDCMImage",
              "identify", "{PROGRAM} {SEEDFILE}")
    image_magick_reproducer.reproduce("CVE-2017-11539", "36aad91", r"C:\vulnerabilities\attachments\memory-leak_output_art_ReadOnePNGImage",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.art")
    image_magick_reproducer.reproduce("CVE-2017-11533", "f0c29cc", r"C:\vulnerabilities\attachments\heap-buffer-overflow-READ-0x7fd806e82db2_output_uil_1500210468.72",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.uil")
    image_magick_reproducer.reproduce("CVE-2017-11753", "5095363", r"C:\vulnerabilities\attachments\heap-buffer-overflow-READ-0x0000006869f0_output_json_1501326140.06.fits",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.json")
    image_magick_reproducer.reproduce("CVE-2017-11753_V2", "ccc71c1", r"C:\vulnerabilities\attachments\heap-buffer-overflow-READ-0x0000006869f0_output_json_1501326140.06.fits",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.json")
    image_magick_reproducer.reproduce("CVE-2017-11310", "8ca3583", r"C:\vulnerabilities\attachments\read_user_chunk_callback.png",
              "identify ", "{PROGRAM} {SEEDFILE}")
    image_magick_reproducer.reproduce("CVE-2017-11446", "787ee25", r"C:\vulnerabilities\attachments\cpu-ReadPESImage",
              "identify", "{PROGRAM} {SEEDFILE}")
    image_magick_reproducer.reproduce("CVE-2017-11141", "cdafbc7", r"C:\vulnerabilities\attachments\ImageMagick-7.0.5-6-memory-exhaustion.MAT",
              "identify", "{PROGRAM} {SEEDFILE}")
    image_magick_reproducer.reproduce("CVE-2017-11535", "b8647f1", r"C:\vulnerabilities\attachments\heap-buffer-overflow-READ-0x7f58970bcdc4_output_ps_1500207243.43",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.ps")
    image_magick_reproducer.reproduce("CVE-2017-11537", "2bbc1b9", r"C:\vulnerabilities\attachments\FPE--0x7eff23c45e38_output_palm_1500208096.66",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.palm")
    image_magick_reproducer.reproduce("CVE-2017-11166", "31b842a", r"C:\vulnerabilities\attachments\ImageMagick-7.0.5-6-memory-exhaustion.XWD",
              "identify", "{PROGRAM} {SEEDFILE}")
    image_magick_reproducer.reproduce("CVE-2017-7606", "b218117", r"C:\vulnerabilities\attachments\00253-imagemagick-outsinde-unsigned-char (2)",
              "identify", "{PROGRAM} {SEEDFILE}")
    image_magick_reproducer.reproduce("CVE-2017-9500", "5d95b4c", r"C:\vulnerabilities\attachments\assertion-failed-in-ResetImageProfileIterator-profile1303_7.0.5-8_Q16",
              "convert", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    image_magick_reproducer.reproduce("CVE-2017-11170", "fbb5e1c", r"C:\vulnerabilities\attachments\ImageMagick-7.0.5-6-memory-exhaustion.VST",
              "identify", "{PROGRAM} {SEEDFILE}")

def libarchive_reproduce():
    libarchive_reproducer = Reproducer(r"C:\vulnerabilities\libarchive_reproduce",
                                       r"C:\vulnerabilities\clean\libarchive",
                                       r"libarchive\libarchive.sln",
                                       r"libarchive",
                                       r"libarchive\bin\Release")
    libarchive_reproducer.reproduce("CVE-2015-8933", "3c7a6dc", r"C:\vulnerabilities\attachments\libarchive-undefined-signed-overflow.tar",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8689_2", "7f17c79", r"C:\vulnerabilities\attachments\118.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8688", "eec077f", r"C:\vulnerabilities\attachments\crash.bz2",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("760", "eec077f", r"C:\vulnerabilities\attachments\113.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("62", "eec077f", r"C:\vulnerabilities\attachments\62.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("25", "eec077f", r"C:\vulnerabilities\attachments\25.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-8687", "e37b620f", r"C:\vulnerabilities\attachments\9.crashes.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-7166", "6e06b1c89", r"C:\vulnerabilities\attachments\selfgz.gz",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-6250", "3014e198", r"C:\vulnerabilities\attachments\libarchiveOverflow.txt",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-5844", "3ad08e0", r"C:\vulnerabilities\attachments\libarchive-signed-int-overflow.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-5844_2", "e6c9668f", r"C:\vulnerabilities\attachments\libarchive-signed-int-overflow.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-5844_3", "e6c9668f", r"C:\vulnerabilities\attachments\libarchive-signed-int-overflow.zip",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-4809", "fd7e0c0", r"C:\vulnerabilities\attachments\c014d4b4-1833-11e6-8ccf-b00bfbedb16c.png",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-4809_2", "fd7e0c0", r"C:\vulnerabilities\attachments\cc6569ea-1833-11e6-88fd-132060c69647.png",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-4809_3", "fd7e0c0", r"C:\vulnerabilities\attachments\d522f84a-1833-11e6-90cc-a1b97770bf9e.png",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10350", "88eb9e1", r"C:\vulnerabilities\attachments\00106-libarchive-heapoverflow-archive_read_format_cab_read_header",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10349", "88eb9e1", r"C:\vulnerabilities\attachments\00105-libarchive-heapoverflow-archive_le32dec",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10209", "42a3408", r"C:\vulnerabilities\attachments\la_segv_archive_wstring_append_from_mbs",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2016-10209_2", "e8a9de5", r"C:\vulnerabilities\attachments\la_segv_archive_wstring_append_from_mbs",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8934", "603454e", r"C:\vulnerabilities\attachments\bsdtar-invalid-read.rar",
                                    "bsdtar", "{PROGRAM} -t -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8932", "f0b1dbb", r"C:\vulnerabilities\attachments\libarchive-undefined-shiftleft",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8930", "01cfbca", r"C:\vulnerabilities\attachments\hang.iso",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8930_2", "39fc593", r"C:\vulnerabilities\attachments\hang.iso",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8928", "64d5628", r"C:\vulnerabilities\attachments\libarchive-oob-process_add_entry.mtree",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8927", "eff35d4", r"C:\vulnerabilities\attachments\pwcrash.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8926", "aab7393", r"C:\vulnerabilities\attachments\segfault.rar",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8925", "1e18cbb71515a22b2a6f1eb4aaadea461929b834", r"C:\vulnerabilities\attachments\read_mtree.mtree",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8924", "bb9b157", r"C:\vulnerabilities\attachments\tar-heap-overflow.tar",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8923", "9e0689c", r"C:\vulnerabilities\attachments\bsdtar-zip-crash-variant1.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8923_2", "9e0689c", r"C:\vulnerabilities\attachments\bsdtar-zip-crash-variant2.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8923_3", "9e0689c", r"C:\vulnerabilities\attachments\bsdtar-zip-crash-variant3.zip",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8922", "d094dc", r"C:\vulnerabilities\attachments\bsdtar-null-ptr.7z",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8921", "1cbc76f", r"C:\vulnerabilities\attachments\invalid-read-overflow.mtree",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8920", "97f964e", r"C:\vulnerabilities\attachments\bsdtar-invalid-read-stack.a",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8919", "e8a2e4d", r"C:\vulnerabilities\attachments\bsdtar-invalid-read.lzh",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8918", "b6ba560", r"C:\vulnerabilities\attachments\memcpy.cab",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")
    libarchive_reproducer.reproduce("CVE-2015-8915", "24f5de6", r"C:\vulnerabilities\attachments\crash.cpio",
                                    "bsdtar", "{PROGRAM} -x -v -f {SEEDFILE}")


def yara_reproduce():
    yara_reproducer = Reproducer(r"C:\vulnerabilities\yara_reproduce",
                                       r"C:\vulnerabilities\clean\yara",
                                       r"yara\windows\vs2015\yara.sln",
                                       r"yara",
                                       r"yara\windows\vs2015\Release")
    yara_reproducer.reproduce("CVE-2017-9465", "992480c", r"C:\vulnerabilities\attachments\yara_ir_yr_arena_write_data.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    exit()
    yara_reproducer.reproduce("CVE-2017-9465_1", "f0a98fb", r"C:\vulnerabilities\attachments\yara_ir_yr_arena_write_data.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9465_2", "a8f58d2", r"C:\vulnerabilities\attachments\yara_ir_yr_arena_write_data.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-9438", "58f72d4", r"C:\vulnerabilities\attachments\yara_so_yr_re_emit.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9438_1", "925bcf3", r"C:\vulnerabilities\attachments\yara_so_yr_re_emit.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9304", "10e8bd3", r"C:\vulnerabilities\attachments\yara_so_yr_re_emit2.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-9304_1", "1aaac7b", r"C:\vulnerabilities\attachments\yara_so_yr_re_emit2.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-8929", "053e67e", r"C:\vulnerabilities\attachments\yara_uaf_sized_string_cmp.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-8929_1", "49fc70e", r"C:\vulnerabilities\attachments\yara_uaf_sized_string_cmp.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-8294", "4cab5b3", r"C:\vulnerabilities\attachments\yara_oobr_yr_re_exec.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-8294_1", "83d7998", r"C:\vulnerabilities\attachments\yara_oobr_yr_re_exec.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-8294_2", "d438c8a", r"C:\vulnerabilities\attachments\yara_oobr_yr_re_exec.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")

    yara_reproducer.reproduce("CVE-2017-5924", "7f02eca", r"C:\vulnerabilities\attachments\yara_uaf_yr_compiler_destroy.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2017-5923", "ab906da", r"C:\vulnerabilities\attachments\yara_hoobr_yyparse_l833.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2016-10211", "890c3f8", r"C:\vulnerabilities\attachments\yara_uaf.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")
    yara_reproducer.reproduce("CVE-2016-10210", "eb491e0", r"C:\vulnerabilities\attachments\yara_null_ptr.txt",
                              "yara32", "{PROGRAM} {SEEDFILE} C:\vulnerabilities\SysinternalsSuite\strings.exe")

def lepton_reproduce():
    lepton_reproducer = Reproducer(r"C:\vulnerabilities\lepton_reproduce",
                                   r"C:\vulnerabilities\lepton\lepton",
                                   r"lepton\lepton.sln",
                                   r"lepton",
                                   r"lepton\Debug")
    lepton_reproducer.reproduce("CVE-2017-8891", "82167c1", r"C:\vulnerabilities\attachments\id_000197,sig_11,src_001438+000435,op_splice,rep_8",
                              "lepton", "{PROGRAM} -unjailed  {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448", "7789d99", r"C:\vulnerabilities\attachments\0.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_1", "7789d99", r"C:\vulnerabilities\attachments\1.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_2", "7789d99", r"C:\vulnerabilities\attachments\2.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_3", "7789d99", r"C:\vulnerabilities\attachments\3.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_4", "7789d99", r"C:\vulnerabilities\attachments\4.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    lepton_reproducer.reproduce("CVE-2017-7448_5", "7789d99", r"C:\vulnerabilities\attachments\5.jpg",
                              "lepton", "{PROGRAM} {SEEDFILE}")
    for ind, commit in enumerate(["91619e2cd62d89f0636eb0a3bc0f2836b20e6520", "fe97442aa30581271e09b5469bd46cfceec41414",
                                  "856e560b6854b02283ec17aa9abb424d4fde4505", "97a9b3c22117e990e16831a3edf75f295c1ee01a"]):
        lepton_reproducer.reproduce("try__" + str(ind),   commit, r"C:\vulnerabilities\attachments\global_bof.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_1_" + str(ind),   commit, r"C:\vulnerabilities\attachments\global_bof2.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_2_" + str(ind),   commit, r"C:\vulnerabilities\attachments\global_bof3.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_3_" + str(ind),   commit, r"C:\vulnerabilities\attachments\invalid_access.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")
        lepton_reproducer.reproduce("try_4_" + str(ind),   commit, r"C:\vulnerabilities\attachments\unknown.jpeg",
                                  "lepton", "{PROGRAM} -singlethread -unjailed -preload {SEEDFILE} {TMP_FILE}.lep")


def openjpeg_reproduce():
    openjpeg_reproducer = Reproducer(r"C:\vulnerabilities\openjpeg_reproduce",
                                   r"C:\vulnerabilities\openjpeg\openjpeg",
                                   r"openjpeg\openjpeg.sln",
                                   r"openjpeg",
                                   r"openjpeg\bin\Release")
    openjpeg_reproducer.reproduce("CVE-2017-14041", "e528531", r"C:\vulnerabilities\attachments\00327-openjpeg-stackoverflow-pgxtoimage.pgx",
                                "opj_compress", "{PROGRAM} -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2k")
    openjpeg_reproducer.reproduce("CVE-2017-14040", "2cd30c2", r"C:\vulnerabilities\attachments\00326-openjpeg-invalidwrite-tgatoimage.tga",
                                "opj_compress", "{PROGRAM} -r 20,10,1 -jpip -EPH -SOP -cinema2K 24 -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2k")
    openjpeg_reproducer.reproduce("CVE-2017-14039", "c535531", r"C:\vulnerabilities\attachments\00322-openjpeg-heapoverflow-opj_t2_encode_packet",
                                "opj_compress", "{PROGRAM} -r 20,10,1 -jpip -EPH -SOP -cinema2K 24 -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2k")
    openjpeg_reproducer.reproduce("CVE-2017-12982", "baf0c1a", r"C:\vulnerabilities\attachments\00315-openjpeg-memallocfailure-opj_aligned_alloc_n",
                                "opj_compress", "{PROGRAM} -n 1 -i {SEEDFILE} -o {TMP_FILE}.j2c")
    openjpeg_reproducer.reproduce("CVE-2016-9112", "d27ccf0", r"C:\vulnerabilities\attachments\poc_855",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.jp2")
    openjpeg_reproducer.reproduce("CVE-2016-7445", "7c86204", r"C:\vulnerabilities\attachments\openjpeg-nullptr-github-issue-842.ppm",
                                "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.j2k")
    openjpeg_reproducer.reproduce("CVE-2016-7445_1", "fac916f", r"C:\vulnerabilities\attachments\openjpeg-nullptr-github-issue-842.ppm",
                                "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.j2k")
    openjpeg_reproducer.reproduce("CVE-2016-7163", "c16bc05", r"C:\vulnerabilities\attachments\poc.jp2",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-7163_1", "ef01f18", r"C:\vulnerabilities\attachments\poc.jp2",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-4796", "ef01f18", r"C:\vulnerabilities\attachments\poc.j2k",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-10507", "16b0e4a", r"C:\vulnerabilities\attachments\poc.bmp",
                                "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-10506", "d27ccf0", r"C:\vulnerabilities\attachments\issue731_2.j2k",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-10506_1", "d27ccf0", r"C:\vulnerabilities\attachments\issue731.j2k",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-10506_2", "d27ccf0", r"C:\vulnerabilities\attachments\poc (1).j2k",
                                "opj_decompress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2016-10504", "397f62c", r"C:\vulnerabilities\attachments\poc (1).bmp",
                                "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")
    openjpeg_reproducer.reproduce("CVE-2015-8871", "940100c", r"C:\vulnerabilities\attachments\poc (1).bmp",
                                "opj_compress", "{PROGRAM} -i {SEEDFILE} -o {TMP_FILE}.png")

def jasper_reproduce():
    # jasper_reproducer = Reproducer(r"C:\vulnerabilities\jasper_reproduce4",
    #                                    r"C:\vulnerabilities\clean\jasper",
    #                                    r"jasper\src\msvc\JasPer.sln",
    #                                    r"jasper",
    #                                    r"jasper\src\msvc\Win32_Release",
    #                                    dsw_path=r"jasper\src\msvc\jasper.dsw")
    # jasper_reproducer.reproduce("CVE-2016-9560", "1abc2e5", r"C:\vulnerabilities\attachments\00047-jasper-stackoverflow-jpc_tsfb_getbands2",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9557", "d42b238", r"C:\vulnerabilities\attachments\00020-jasper-signedintoverflow-jas_image_c",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9387", "d91198a", r"C:\vulnerabilities\attachments\00003-jasper-assert-jas_matrix_t",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9388", "411a406", r"C:\vulnerabilities\attachments\00005-jasper-assert-ras_getcmap",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9389", "dee11ec", r"C:\vulnerabilities\attachments\00006-jasper-assert-jpc_irct",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9389_1", "dee11ec", r"C:\vulnerabilities\attachments\00008-jasper-assert-jpc_iict",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9390", "ba2b9d0", r"C:\vulnerabilities\attachments\00007-jasper-assert-jas_matrix_t",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9391", "1e84674", r"C:\vulnerabilities\attachments\00014-jasper-assert-jpc_bitstream_getbits",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9392", "f703806", r"C:\vulnerabilities\attachments\00012-jasper-assert-calcstepsizes",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9393", "f703806", r"C:\vulnerabilities\attachments\00013-jasper-assert-jpc_pi_nextrpcl",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9394", "f703806", r"C:\vulnerabilities\attachments\00016-jasper-assert-jas_matrix_t",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9395", "d42b238", r"C:\vulnerabilities\attachments\00043-jasper-assert-jas_matrix_t",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-9262", "634ce8e", r"C:\vulnerabilities\attachments\00028-jasper-uaf-jas_realloc",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8887", "e24bdc7", r"C:\vulnerabilities\attachments\00002-jasper-NULLptr-jp2_colr_destroy",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8886", "6553664", r"C:\vulnerabilities\attachments\2.crashes",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8885", "5d66894", r"C:\vulnerabilities\attachments\9.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8885_1", "8f62b47", r"C:\vulnerabilities\attachments\9.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8885_2", "8f62b47", r"C:\vulnerabilities\attachments\10.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8885_3", "5d66894", r"C:\vulnerabilities\attachments\.crashes",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8884", "5d66894", r"C:\vulnerabilities\attachments\5.crashes",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8883", "33cc2cf", r"C:\vulnerabilities\attachments\jasper-assert-jpc_dec_tiledecode.jp2",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8882", "69a1439", r"C:\vulnerabilities\attachments\jasper-nullptr-jpc_pi_destroy.jp2",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8693", "44a524e", r"C:\vulnerabilities\attachments\1.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8693_1", "668e682", r"C:\vulnerabilities\attachments\1.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8693_2", "668e682", r"C:\vulnerabilities\attachments\jasper-doublefree-mem_close.jpg",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8693_3", "44a524e", r"C:\vulnerabilities\attachments\jasper-doublefree-mem_close.jpg",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8692", "d8c2604", r"C:\vulnerabilities\attachments\11.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8692_1", "d8c2604", r"C:\vulnerabilities\attachments\12.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8691", "d8c2604", r"C:\vulnerabilities\attachments\12.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8691_1", "d8c2604", r"C:\vulnerabilities\attachments\11.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8690_1", "8f62b47", r"C:\vulnerabilities\attachments\9.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8690_2", "8f62b47", r"C:\vulnerabilities\attachments\10.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8690_3", "8f62b47", r"C:\vulnerabilities\attachments\11.crash",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-8690", "5d66894", r"C:\vulnerabilities\attachments\5.crashes",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-10251", "1f0dfe5a", r"C:\vulnerabilities\attachments\00029-jasper-uninitvalue-jpc_pi_nextcprl",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-10250", "bdfe95a6e", r"C:\vulnerabilities\attachments\00002-jasper-NULLptr-jp2_colr_destroy",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")
    # jasper_reproducer.reproduce("CVE-2016-10249", "988f836", r"C:\vulnerabilities\attachments\00001-jasper-heapoverflow-jpc_dec_tiledecode",
    #                                 "imginfo", "{PROGRAM} -f {SEEDFILE}")

    jasper_reproducer = Reproducer(r"C:\vulnerabilities\jasper_reproduce4",
                                   r"C:\vulnerabilities\clean\jasper",
                                   r"jasper\bin\JasPer.sln",
                                   r"jasper",
                                   r"jasper\bin\src\appl",
                                   extended_path=r"jasper\bin\src\libjasper")
    jasper_reproducer.reproduce("CVE-2017-6850", "e96fc4f",
                                r"C:\vulnerabilities\attachments\00124-jasper-nullptr-jp2_cdef_destroy",
                                "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_2", "a105443",
                                r"C:\vulnerabilities\attachments\00124-jasper-nullptr-jp2_cdef_destroy",
                                "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_3", "607c263",
                                r"C:\vulnerabilities\attachments\00124-jasper-nullptr-jp2_cdef_destroy",
                                "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_4", "9c88f65",
                                r"C:\vulnerabilities\attachments\00124-jasper-nullptr-jp2_cdef_destroy",
                                "imginfo", "{PROGRAM} -f {SEEDFILE}")
    jasper_reproducer.reproduce("CVE-2017-6850_5", "562c0a7",
                                r"C:\vulnerabilities\attachments\00124-jasper-nullptr-jp2_cdef_destroy",
                                "imginfo", "{PROGRAM} -f {SEEDFILE}")


def libtiff_reproduce():
    libtiff_reproducer = Reproducer(r"C:\vulnerabilities\libtiff_reproduce",
                                       r"C:\vulnerabilities\clean\libtiff",
                                       r"libtiff\tiff.sln",
                                       r"libtiff",
                                       r"libtiff\tools\Release",
                                       r"libtiff\libtiff\Release")
    libtiff_reproducer.reproduce("CVE-2017-5225", "5c080298d59efa53264d7248bbe3a04660db6ef7", r"C:\vulnerabilities\attachments\poc.tiff",
                                    "tiffcp", "{PROGRAM} -p separate {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-9297", "30c9234c7fd0dd5e8b1e83ad44370c875a0270ed", r"C:\vulnerabilities\attachments\test000",
                                    "tiffinfo", "{PROGRAM} -i {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2016-10095", "4d4fa0b68ae9ae038959ee4f69ebe288ec892f06", r"C:\vulnerabilities\attachments\00104-libtiff-stackoverflow-_TIFFVGetField",
                                    "tiffsplit", "{PROGRAM} {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2016-10268", "5397a417e61258c69209904e652a1f409ec3b9df", r"C:\vulnerabilities\attachments\00068-libtiff-heapoverflow-_tiffWriteProc",
                                    "tiffcp", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-10269", "9a72a69e035ee70ff5c41541c8c61cd97990d018", r"C:\vulnerabilities\attachments\00074-libtiff-heapoverflow-TIFFFillStrip",
                                    "tiffcp", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-10270", "9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a", r"C:\vulnerabilities\attachments\00100-libtiff-heapoverflow-_TIFFFax3fillruns",
                                    "tiffcrop", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-10271", "9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a", r"C:\vulnerabilities\attachments\00102-libtiff-heapoverflow-_TIFFmemcpy",
                                    "tiffcrop", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    # libtiff_reproducer.reproduce("CVE-2016-10093", "9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a", r"C:\vulnerabilities\attachments\00103-libtiff-heapoverflow-NeXTDecode",
    #                                 "tiffcrop", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-10272", "9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a", r"C:\vulnerabilities\attachments\00102-libtiff-heapoverflow-_TIFFmemcpy",
                                    "tiffcrop", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-10092", "b4b41925115059b49f97432bda0613411df2f686", r"C:\vulnerabilities\attachments\00067-libtiff-heapoverflow-tiffcp",
                                    "tiffcp", "{PROGRAM} -i {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2015-8784", "b18012dae552f85dcc5c57d3bf4e997a15b1cc1c", r"C:\vulnerabilities\attachments\libtiff5.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2015-8783", "aaab5c3c9d2a2c6984f23ccbc79702610439bc65", r"C:\vulnerabilities\attachments\broken_2.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2015-8683", "aaab5c3c9d2a2c6984f23ccbc79702610439bc65", r"C:\vulnerabilities\attachments\broken_2.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2014-9655", "0be02fe369e2fabf71856cd8c69d5659710d794d", r"C:\vulnerabilities\attachments\libtiff-cvs-1.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2014-9655_1", "40a5955cbf0df62b1f9e9bd7d9657b0070725d19", r"C:\vulnerabilities\attachments\libtiff-cvs-1.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2014-9655_2", "0be02fe369e2fabf71856cd8c69d5659710d794d", r"C:\vulnerabilities\attachments\libtiff-cvs-2.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2014-9655_3", "40a5955cbf0df62b1f9e9bd7d9657b0070725d19", r"C:\vulnerabilities\attachments\libtiff-cvs-2.tif",
                                    "tiffinfo", "{PROGRAM} -d {SEEDFILE}")
    libtiff_reproducer.reproduce("CVE-2014-9330", "662f74445b2fea2eeb759c6524661118aef567ca", r"C:\vulnerabilities\attachments\crash.bmp",
                                    "bmp2tiff", "{PROGRAM} {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2013-4243", "2f756ac2adc513c97b58144471a1a0887a2650ae", r"C:\vulnerabilities\attachments\008.gif",
                                    "gif2tiff", "{PROGRAM} {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-9453", "7399a6f13bd6f4d0dfb7b9d0a25fafa86caa9b50", r"C:\vulnerabilities\attachments\1 (1).tiff",
                                    "gif2tiff", "{PROGRAM} {SEEDFILE} {TMP_FILE}")
    libtiff_reproducer.reproduce("CVE-2016-9453_!", "a7abf0ba9044810d8d3104045e3bd840d1569d51", r"C:\vulnerabilities\attachments\test049",
                                    "tiffsplit", "{PROGRAM} {SEEDFILE}")

def imageworsener_reproduce():
    imageworsener_reproducer = Reproducer(r"C:\vulnerabilities\imageworsener_reproduce",
                                       r"C:\vulnerabilities\clean\imageworsener",
                                       r"imageworsener\scripts\imagew2008.sln",
                                       r"imageworsener",
                                       r"imageworsener\Release32",
                                       dsw_path=r"imageworsener\scripts\imagew2008.sln")
    imageworsener_reproducer.reproduce("CVE-2017-9201", "dc49c807926b96e503bd7c0dec35119eecd6c6fe",
                                 r"C:\vulnerabilities\attachments\00278-imageworsener-fpe-outside-int",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9202", "dc49c807926b96e503bd7c0dec35119eecd6c6fe",
                                 r"C:\vulnerabilities\attachments\00279-imageworsener-fpe-outside-int_2",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9203", "a4f247707f08e322f0b41e82c3e06e224240a654",
                                 r"C:\vulnerabilities\attachments\00280-imageworsener-oob-iw_channelinfo_out",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9204", "b45cb1b665a14b0175b9cb1502ef7168e1fe0d5d",
                                 r"C:\vulnerabilities\attachments\00281-imageworsener-invalidread-iw_get_ui16le",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9205", "b45cb1b665a14b0175b9cb1502ef7168e1fe0d5d",
                                 r"C:\vulnerabilities\attachments\00282-imageworsener-invalidread-iw_get_ui16be",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9206", "b45cb1b665a14b0175b9cb1502ef7168e1fe0d5d",
                                 r"C:\vulnerabilities\attachments\00283-imageworsener-heapoverflow-iw_get_ui16le",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9207", "b45cb1b665a14b0175b9cb1502ef7168e1fe0d5d",
                                 r"C:\vulnerabilities\attachments\00284-imageworsener-heapoverflow-iw_get_ui16be",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9094", "a75fd48",
                                 r"C:\vulnerabilities\attachments\183df600-3a7c-11e7-8f6d-88b61e33bb08.jpg",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-9093", "62bfbfb",
                                 r"C:\vulnerabilities\attachments\9b1f87c4-3823-11e7-85d8-2136f4a9ad59.jpg",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-8327", "86564051db45b466e5f667111ce00b5eeedc8fb6",
                                 r"C:\vulnerabilities\attachments\00276-imageworsener-memallocfailure",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-8326", "a00183107d4b84bc8a714290e824ca9c68dac738",
                                 r"C:\vulnerabilities\attachments\00271-imageworsener-leftshift",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-8325", "86564051db45b466e5f667111ce00b5eeedc8fb6",
                                 r"C:\vulnerabilities\attachments\00269-imageworsener-heapoverflow-iw_process_cols_to_intermediate",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-7962", "ca3356eb49fee03e2eaf6b6aff826988c1122d93",
                                 r"C:\vulnerabilities\attachments\00270-imageworsener-FPE-iwgif_record_pixel",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE} -outfmt bmp")
    imageworsener_reproducer.reproduce("CVE-2017-7940", "5fa4864",
                                 r"C:\vulnerabilities\attachments\topnm-memory-leak-in-imagew-cmd",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.pnm")
    imageworsener_reproducer.reproduce("CVE-2017-7939", "bb321cf",
                                 r"C:\vulnerabilities\attachments\1071-stack-buffer-overflow-imagew-pnm",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    imageworsener_reproducer.reproduce("CVE-2017-7624", "49912f8",
                                 r"C:\vulnerabilities\attachments\\1048-memoryleak-imagew-cmd",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    imageworsener_reproducer.reproduce("CVE-2017-7623", "f9c12fa",
                                 r"C:\vulnerabilities\attachments\\1049-heap-buffer-overflow-imagew-miff",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    imageworsener_reproducer.reproduce("CVE-2017-7454", "dc74009",
                                 r"C:\vulnerabilities\attachments\\1111-heap-buffer-overslow-imagew-gif_223_5",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    imageworsener_reproducer.reproduce("CVE-2017-7453", "dc74009",
                                 r"C:\vulnerabilities\attachments\\1016-NULL-ptr-imagew-gif_223_5",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")
    imageworsener_reproducer.reproduce("CVE-2017-7452", "4500070",
                                 r"C:\vulnerabilities\attachments\\2712-NULL-ptr-imagew-bmp_419_2",
                                 "imagew", "{PROGRAM} {SEEDFILE} {TMP_FILE}.png")


def opencv_reproduce():
    opencv_reproducer = Reproducer(r"C:\vulnerabilities\opencv_reproduce2",
                                       r"C:\vulnerabilities\clean\opencv",
                                       r"opencv\bin\OpenCV.sln",
                                       r"opencv",
                                       r"opencv\bin\bin\Release")
    opencv_reproducer.reproduce("CVE-2017-14136", "aacae2065744adb05e858d327198c7bbe7f452b0",
                                 r"C:\vulnerabilities\attachments\12-opencv-outbound-write-FillColorRow1",
                                 "opencv_test", "{PROGRAM} {SEEDFILE}")

def wireshark_reproduce():
    wireshark_reproducer = Reproducer(r"C:\vulnerabilities\wireshark_reproduce1",
                                       r"C:\vulnerabilities\clean\wireshark",
                                       r"wireshark\wireshark.sln",
                                       r"wireshark",
                                       r"wireshark\run\Release",
                                      dsw_path=r"wireshark\wireshark.sln")
    wireshark_data_file = r"C:\temp\wireshark.csv"
    data = []
    with open(wireshark_data_file) as f:
        data = list(csv.reader(f))[1:]
    for cve, reproduce_file_name, commit in list(reversed(data))[4::5]:
        wireshark_reproducer.reproduce(cve, commit, reproduce_file_name, "tshark", "{PROGRAM} -r {SEEDFILE}")

if __name__ == "__main__":
    # opencv_reproduce()
    # wireshark_reproduce()
    # yara_reproduce()
    # lepton_reproduce()
    # image_magick_reproduce()
    # jasper_reproduce()
    # libarchive_reproduce()
    # openjpeg_reproduce()
    libtiff_reproduce()
    imageworsener_reproduce()


    # reproduce("CVE-0000-0000", "91cc3f3", r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5510\exploit\18.psb", "magick", "{PROGRAM} {SEEDFILE} NUL")