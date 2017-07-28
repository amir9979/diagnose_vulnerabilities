import random
import sys
import glob
import os
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
ITERATIONS = 100

def fuzz_sedd_file(example_file, output_dir, iterations):
    for fuzzer_class in FUZZERS:
        for seed in range(iterations):
            range_seed = random.randint(0, sys.maxint)
            seedfile = SeedFile(output_dir, example_file)
            with fuzzer_class(seedfile, output_dir, range_seed, seed, {}) as fuzzer:
                print fuzzer.__class__, range_seed
                fuzzer.fuzz()

def fuzz_project_dir(fuzzing_dir):
    output_fuzzing = os.path.join(fuzzing_dir, FUZING_OUTPUT_DIR)
    if not os.path.exists(output_fuzzing):
        os.mkdir(output_fuzzing)
    for seed_example in glob.glob(os.path.join(os.path.join(fuzzing_dir, "seedfiles"), "*")):
        fuzz_sedd_file(seed_example, output_fuzzing, ITERATIONS)



if __name__ == "__main__":
    fuzz_sedd_file(r"C:\Temp\g.png", r"C:\Temp\fuzz", 1000)