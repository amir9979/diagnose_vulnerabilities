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


if __name__ == "__main__":
    fuzz_sedd_file(r"C:\Temp\g.png", r"C:\Temp\fuzz", 1000)