### BEGIN LICENSE ###
### Use of the FOE system and related source code is subject to the terms
### of the license below. Please note that winprocess.py and
### killableprocess.py are subject to different licenses; see those files for
### their respective licenses.
### 
### ------------------------------------------------------------------------
### Copyright (C) 2013 Carnegie Mellon University. All Rights Reserved.
### ------------------------------------------------------------------------
### Redistribution and use in source and binary forms, with or without
### modification, are permitted provided that the following conditions are
### met:
### 
### 1. Redistributions of source code must retain the above copyright
###    notice, this list of conditions and the following acknowledgments
###    and disclaimers.
### 
### 2. Redistributions in binary form must reproduce the above copyright
###    notice, this list of conditions and the following disclaimer in the
###    documentation and/or other materials provided with the distribution.
### 
### 3. All advertising materials for third-party software mentioning
###    features or use of this software must display the following
###    disclaimer:
### 
###    "Neither Carnegie Mellon University nor its Software Engineering
###     Institute have reviewed or endorsed this software"
### 
### 4. The names "Department of Homeland Security," "Carnegie Mellon
###    University," "CERT" and/or "Software Engineering Institute" shall
###    not be used to endorse or promote products derived from this software
###    without prior written permission. For written permission, please
###    contact permission@sei.cmu.edu.
### 
### 5. Products derived from this software may not be called "CERT" nor
###    may "CERT" appear in their names without prior written permission of
###    permission@sei.cmu.edu.
### 
### 6. Redistributions of any form whatsoever must retain the following
###    acknowledgment:
### 
###    "This product includes software developed by CERT with funding
###     and support from the Department of Homeland Security under
###     Contract No. FA 8721-05-C-0003."
### 
### THIS SOFTWARE IS PROVIDED BY CARNEGIE MELLON UNIVERSITY ``AS IS'' AND
### CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
### EXPRESS OR IMPLIED, AS TO ANY MATTER, AND ALL SUCH WARRANTIES, INCLUDING
### WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE
### EXPRESSLY DISCLAIMED. WITHOUT LIMITING THE GENERALITY OF THE FOREGOING,
### CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
### RELATING TO EXCLUSIVITY, INFORMATIONAL CONTENT, ERROR-FREE OPERATION,
### RESULTS TO BE OBTAINED FROM USE, FREEDOM FROM PATENT, TRADEMARK AND
### COPYRIGHT INFRINGEMENT AND/OR FREEDOM FROM THEFT OF TRADE SECRETS.
### END LICENSE ###

'''
Created on Feb 14, 2012

@organization: cert.org
'''

import unittest
import os
import shutil
from certfuzz.fuzzers.bytemut import fuzz
from certfuzz.fuzzers.crmut import CRMutFuzzer
from certfuzz.test import MockSeedfile, MockRange
import tempfile
from certfuzz.fuzztools.hamming import bytewise_hd
import copy

class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.sf.value = bytearray(self.sf.value)
        self.chars_inserted = 0
        for i in xrange(0, len(self.sf.value), 10):
            self.sf.value[i] = 0x0D
            self.chars_inserted += 1

        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        rng_seed = 0
        iteration = 0
        self.options = {'min_ratio': 0.1, 'max_ratio': 0.2}
        self.args = (seedfile_obj, outdir_base, rng_seed, iteration, self.options)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _fail_if_not_fuzzed(self, fuzzed):
        for c in fuzzed:
            if c == 'A' or c == 0x0D:
                continue
            else:
                # skip over the else: clause
                break
        else:
            self.fail('Input not fuzzed')

    def _test_fuzz(self, inputlen=1000, iterations=100, rangelist=None):
        _input = bytearray('A' * inputlen)
        # sub in null chars
        chars_inserted = 0
        for i in xrange(0, inputlen, 10):
            _input[i] = 0x0D
            chars_inserted += 1

        for i in xrange(iterations):
            fuzzed = fuzz(fuzz_input=copy.copy(_input),
                                seed_val=0,
                                jump_idx=i,
                                ratio_min=0.1,
                                ratio_max=0.3,
                                range_list=rangelist,
                                fuzzable_chars=[0x0D]
                              )
            self.assertEqual(inputlen, len(fuzzed))
            self.assertNotEqual(_input, fuzzed)
            hd = bytewise_hd(_input, fuzzed)

            self.assertGreater(hd, 0)
            self.assertLessEqual(hd, chars_inserted)

            actual_ratio = hd / float(chars_inserted)
            self.assertGreaterEqual(actual_ratio, 0.1)
            self.assertLessEqual(actual_ratio, 0.3)

    def test_fuzz(self):
        self._test_fuzz()

    def test_fuzz_longinput(self):
        '''
        Test fuzz method with abnormally long input to find memory bugs
        '''
        self._test_fuzz(inputlen=10000000, iterations=2)

    def test_fuzz_rangelist(self):
        inputlen = 10000
        iterations = 100
        r = [(0, 100), (600, 1000), (3000, 10000)]
        _input = bytearray('A' * inputlen)
        # sub in null chars
        chars_inserted = 0
        for i in xrange(0, inputlen, 10):
            _input[i] = 0x0D
            chars_inserted += 1

        for i in xrange(iterations):
            fuzzed = fuzz(fuzz_input=copy.copy(_input),
                                seed_val=0,
                                jump_idx=i,
                                ratio_min=0.1,
                                ratio_max=0.3,
                                range_list=r,
                                fuzzable_chars=[0x0D],
                              )
            self.assertEqual(inputlen, len(fuzzed))
            self.assertNotEqual(_input, fuzzed)

            for (a, b) in r:
                # make sure we didn't change the exclude ranges
                self.assertEqual(_input[a:b + 1], fuzzed[a:b + 1])

            hd = bytewise_hd(_input, fuzzed)

            self.assertGreater(hd, 0)
            self.assertLess(hd, chars_inserted)

            # we excluded all but 2500 bytes in r above
            actual_ratio = hd / 2500.0
            self.assertGreaterEqual(actual_ratio, 0.01)
            self.assertLessEqual(actual_ratio, 0.03)

    def test_nullmutfuzzer_fuzz(self):
        self.assertTrue(self.sf.len > 0)
        for i in xrange(100):
            with CRMutFuzzer(*self.args) as f:
                f.iteration = i
                f._fuzz()
                # same length, different output
                self.assertEqual(self.sf.len, len(f.fuzzed))
                self._fail_if_not_fuzzed(f.input)
                # confirm ratio
#                self.assertGreaterEqual(f.fuzzed_byte_ratio() / self.chars_inserted, MockRange().min)
#                self.assertLessEqual(f.fuzzed_byte_ratio() / self.chars_inserted, MockRange().max)

    def test_consistency(self):
        # ensure that we get the same result 20 times in a row
        # for 50 different iterations
        last_result = None
        last_x = None
        for x in range(50):
            if x != last_x:
                last_result = None
            last_x = x
            for _ in range(20):
                with CRMutFuzzer(self.sf, self.outdir, x, x, self.options) as f:
                    f._fuzz()
                    result = str(f.fuzzed)
                    if last_result:
                        self.assertEqual(result, last_result)
                    else:
                        last_result = result

#    def test_is_minimizable(self):
#        f = CRMutFuzzer(*self.args)
#        self.assertTrue(f.is_minimizable)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
