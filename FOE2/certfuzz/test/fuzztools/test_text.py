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
Created on Apr 10, 2012

@organization: cert.org
'''
import unittest
from certfuzz.fuzztools import text
import math
import tempfile
import shutil
import os
import random

class Test(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test__pattern(self):
        iterables = ['ABC', 'abc', '012']
        for length in range(3, 1000):
            pat = text._pattern(iterables, length)
            self.assertEqual(length, len(pat))
            self.assertTrue(pat.startswith('Aa0'))
            if length > 100:
                self.assertTrue('Cc2' in pat)

        # make sure it rolls over
        # each iterable has 3 possible values
        # and there are 3 iterables thus 3 chars per token
        rollover_pos = 3 * 3 * 3 * 3
        # so we want to overshoot by one token
        # to ensure that we rollover to the start token Aa0 again
        rollover_str = text._pattern(iterables, rollover_pos + 3)
        self.assertTrue(rollover_str.endswith('Cc2Aa0'))

    def test_metasploit_pattern_orig(self):
        for length in range(3, 1000):
            pat = text.metasploit_pattern_orig(length)
            self.assertEqual(length, len(pat))
            self.assertTrue(pat.startswith('Aa0'))
            if length > 101:
                self.assertEqual('Ad3', pat[99:102])

    def test_metasploit_pattern_extended(self):
        for length in range(6, 1000):
            pat = text.metasploit_pattern_extended(length)
            self.assertEqual(length, len(pat))
            self.assertTrue(pat.startswith('AAaa00'))
            if length > 101:
                self.assertEqual('AAaa16', pat[96:102])

    def test__enumerate_string(self):
        s = 'x____' * 1000

        occurrences = sorted(random.sample(population=range(0, len(s), 5), k=102))
        result = text._enumerate_string(s, occurrences)
        # length should be unchanged
        self.assertEqual(len(s), len(result))

        # convert result to string
        result = str(result)
        self.assertNotEqual(s, result)
        # check 1 digit
        self.assertTrue('____1____' in result)
        # check 2 digit
        self.assertTrue('___10___' in result)
        # check 3 digit
        self.assertTrue('__100__' in result)

    def test_enumerate_string(self):
        (fd, f) = tempfile.mkstemp(suffix='.foo', dir=self.tempdir)
        os.write(fd, 'AAAAxxxAAAAxxxxxAAAAxAAAA')
        os.close(fd)
        root, ext = os.path.splitext(f)
        expected_newpath = '{}-enum{}'.format(root, ext)

        newpath = text.enumerate_string(f, 'AAAA')
        self.assertTrue(newpath.endswith('-enum.foo'))

        self.assertEqual(expected_newpath, newpath)
        self.assertTrue(os.path.exists(expected_newpath))

        with open(newpath, 'rb') as fp:
            content = fp.read()
            self.assertEqual('0AAAxxx1AAAxxxxx2AAAx3AAA', content)
        os.remove(newpath)
        os.remove(f)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
