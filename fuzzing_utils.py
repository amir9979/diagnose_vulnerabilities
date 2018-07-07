import os
import random
import sys
import utils
from FOE2.certfuzz.file_handlers.seedfile import SeedFile
from FOE2.certfuzz.fuzzers.bitmut import BitMutFuzzer
from FOE2.certfuzz.fuzzers.bytemut import ByteMutFuzzer
from FOE2.certfuzz.fuzzers.copy import CopyFuzzer
from FOE2.certfuzz.fuzzers.crlfmut import CRLFMutFuzzer
from FOE2.certfuzz.fuzzers.crmut import CRMutFuzzer
from FOE2.certfuzz.fuzzers.drop import DropFuzzer
from FOE2.certfuzz.fuzzers.insert import InsertFuzzer
from FOE2.certfuzz.fuzzers.nullmut import NullMutFuzzer
from FOE2.certfuzz.fuzzers.swap import SwapFuzzer
from FOE2.certfuzz.fuzzers.truncate import TruncateFuzzer
from FOE2.certfuzz.fuzzers.wave import WaveFuzzer

FUZING_OUTPUT_DIR = r"fuzzed_seedfiles"
FUZING_WORKING_DIR = r"fuzzed_working_dir"
FUZZERS = [BitMutFuzzer, ByteMutFuzzer, CopyFuzzer, CRLFMutFuzzer, CRMutFuzzer, DropFuzzer, InsertFuzzer, NullMutFuzzer,
           SwapFuzzer, TruncateFuzzer, WaveFuzzer]
FUZZERS = [ByteMutFuzzer]


def fuzz_seed_file(example_file, output_dir, iterations, ratio_min, ratio_max, range_seed=None):
    fuzzed_files = []
    for fuzzer_class in FUZZERS:
        for seed in range(iterations):
            if range_seed is None:
                range_seed = random.randint(0, sys.maxint)
            seedfile = SeedFile(output_dir, ratio_min, ratio_max, example_file)
            with fuzzer_class(seedfile, output_dir, range_seed, seed, {}) as fuzzer:
                fuzzer.fuzz()
                fuzzed_files.append(fuzzer.output_file_path)
    return fuzzed_files


def fuzz_project_dir(seedfiles_dir, output_dir, iterations, ratio_min=0.0, ratio_max=1.0):
    fuzzed_files = []
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    for seed_example in utils.get_files_in_dir(seedfiles_dir):
        fuzzed_files.extend(fuzz_seed_file(seed_example, output_dir, iterations, ratio_min, ratio_max))
    return fuzzed_files