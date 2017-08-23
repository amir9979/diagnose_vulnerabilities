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

def fuzz_sedd_file(example_file, output_dir, iterations):
    for fuzzer_class in FUZZERS:
        for seed in range(iterations):
            range_seed = random.randint(0, sys.maxint)
            seedfile = SeedFile(output_dir, example_file)
            with fuzzer_class(seedfile, output_dir, range_seed, seed, {}) as fuzzer:
                print fuzzer.__class__, range_seed
                fuzzer.fuzz()


def fuzz_project_dir(seedfiles_dir, output_dir, iterations):
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    for seed_example in utils.get_files_in_dir(seedfiles_dir):
        fuzz_sedd_file(seed_example, output_dir, iterations)