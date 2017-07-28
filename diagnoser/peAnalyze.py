import pefile
import os


already_imported_modules = []

FUNCS_DICT= []

def getImportedModules(pe_file_to_analyze):
    global already_imported_modules
    already_imported_modules.append(pe_file_to_analyze)
    if not os.path.exists(pe_file_to_analyze):
        return []
    pe = pefile.PE(pe_file_to_analyze)
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        path = os.path.join(os.path.dirname(pe_file_to_analyze), entry.dll)
        print entry.dll
        if os.path.exists(path) and path not in already_imported_modules:
            getImportedModules(path)
    return already_imported_modules


def init_func_dict(binary_file):
    global FUNCS_DICT
    if len(FUNCS_DICT) == 0:
        pe = pefile.PE(binary_file)
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                FUNCS_DICT[func.name] = entry.dll
                FUNCS_DICT["_" + func.name] = entry.dll
                FUNCS_DICT["__" + func.name] = entry.dll

imported = getImportedModules(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe")
print imported