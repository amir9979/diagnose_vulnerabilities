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
Created on Apr 8, 2011

@organization: cert.org
'''
import os
import tempfile
from certfuzz.fuzztools import hamming
from certfuzz.minimizer import Minimizer
import shutil
from certfuzz.file_handlers.basicfile import BasicFile
import certfuzz
import unittest

class Mock(object):
    def __init__(self, *args, **kwargs):
        pass

class MockCfg(Mock):
    program = 'a'
    debugger_timeout = 1
    killprocname = 'a'
    exclude_unmapped_frames = False
    backtracelevels = 5

    def get_command_args_list(self, dummy):
        return tuple('abcd')

class MockCrasher(Mock):
    def __init__(self):
        fd, f = tempfile.mkstemp(suffix='.ext', prefix='fileroot')
        os.close(fd)
        self.fuzzedfile = BasicFile(f)
        self.debugger_template = 'foo'

    def set_debugger_template(self, dummy):
        pass

class MockDbgOut(Mock):
    is_crash = False
    total_stack_corruption = False

    def get_crash_signature(self, *dummyargs):
        return 'AAAAA'

class MockDebugger(Mock):
    def get(self):
        return MockDebugger

    def go(self):
        return MockDbgOut()

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        self.cfg = MockCfg()
        self.crash = MockCrasher()
        self.tempdir = tempfile.mkdtemp(prefix='minimizer_test_')
        self.crash_dst_dir = tempfile.mkdtemp(prefix='crash_', dir=self.tempdir)
        (fd, self.logfile) = tempfile.mkstemp(dir=self.tempdir)
        os.close(fd)
        os.remove(self.logfile)
        self.assertFalse(os.path.exists(self.logfile))
        certfuzz.minimizer.minimizer_base.debuggers = MockDebugger()

        self.m = Minimizer(cfg=self.cfg, crash=self.crash,
                           crash_dst_dir=self.crash_dst_dir,
                           logfile=self.logfile, tempdir=self.tempdir)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_go(self):
        pass

    def test_have_we_seen_this_file_before(self):
        self.m.newfuzzed_md5 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

        self.assertFalse(self.m.have_we_seen_this_file_before())
        self.assertTrue(self.m.have_we_seen_this_file_before())

    def test_is_same_crash(self):
        pass

    def test_print_intermediate_log(self):
        pass

    def test_set_discard_chance(self):
        self.m.seed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.m.fuzzed = "abcdefghijklmnopqrstuvwxyz"
        self.m.min_distance = hamming.bytewise_hd(self.m.seed, self.m.fuzzed)
        self.assertEqual(self.m.min_distance, 26)

        for tsg in xrange(1, 20):
            self.m.target_size_guess = tsg
            self.m.set_discard_chance()
            self.assertAlmostEqual(self.m.discard_chance, 1.0 / (1.0 + tsg))

    def test_set_n_misses(self):
        pass

    def test_swap_bytes(self):
        seed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fuzzed = "abcdefghijklmnopqrstuvwxyz"

        for dc in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
            self.m.discard_chance = dc
            self.m.seed = seed
            self.m.fuzzed = fuzzed
            self.m.min_distance = 26
            self.m.swap_func = self.m.bytewise_swap2
            self.m.swap_bytes()
            self.assertTrue(0 < self.m.newfuzzed_hd)
            self.assertTrue(self.m.newfuzzed_hd <= 26)
            self.assertNotEqual(self.m.newfuzzed, fuzzed)
            self.assertNotEqual(self.m.newfuzzed, seed)

    def test_update_probabilities(self):
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
