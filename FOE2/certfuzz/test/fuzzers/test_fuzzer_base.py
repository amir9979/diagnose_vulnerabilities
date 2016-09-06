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
from certfuzz.fuzzers import Fuzzer
from certfuzz.test import MockSeedfile
import shutil
from certfuzz.fuzzers import MinimizableFuzzer
import tempfile
from certfuzz.fuzzers.fuzzer_base import _fuzzable

class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        rng_seed = 0
        iteration = 0
        options = {}
        self.args = (seedfile_obj, outdir_base, rng_seed, iteration, options)

    def tearDown(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_read_input(self):
        with Fuzzer(*self.args) as f:
            self.assertEqual(f.input, self.sf.read())

    def test_no_write_if_not_fuzzed(self):
        with Fuzzer(*self.args) as f:
            self.assertFalse(os.path.exists(f.output_file_path), f.output_file_path)
            # if we haven't fuzzed, don't write
            f.fuzzed = None
            f.write_fuzzed()
            self.assertFalse(os.path.exists(f.output_file_path))

    def test_write_fuzzed(self):
        with Fuzzer(*self.args) as f:

            self.assertFalse(os.path.exists(f.output_file_path), f.output_file_path)

            # if we have fuzzed, write
            f.fuzzed = 'abcd'
            f.write_fuzzed()
            self.assertTrue(os.path.exists(f.output_file_path))
            self.assertEqual(os.path.getsize(f.output_file_path), len(f.fuzzed))
            with open(f.output_file_path, 'rb') as fd:
                written = fd.read()
                self.assertEqual(written, f.fuzzed)

    def test_minimizable_attribute(self):
        yes = MinimizableFuzzer(*self.args)
        self.assertTrue(yes.is_minimizable)

        no = Fuzzer(*self.args)
        self.assertFalse(no.is_minimizable)

    def test_fuzzable(self):
        r = [(0, 100), (600, 1000), (3000, 10000)]
        for x in xrange(10000):
            if 0 <= x <= 100:
                self.assertFalse(_fuzzable(x, r), 'x=%d' % x)
            elif 600 <= x <= 1000:
                self.assertFalse(_fuzzable(x, r), 'x=%d' % x)
            elif 3000 <= x <= 10000:
                self.assertFalse(_fuzzable(x, r), 'x=%d' % x)
            else:
                self.assertTrue(_fuzzable(x, r), 'x=%d' % x)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
