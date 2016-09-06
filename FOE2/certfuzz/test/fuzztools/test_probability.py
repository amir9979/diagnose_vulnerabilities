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
from certfuzz.fuzztools.probability import FuzzRun
import math
from certfuzz.fuzztools.probability import lnfactorial
from certfuzz.fuzztools.probability import shot_size
from certfuzz.fuzztools.probability import misses_until_quit
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        N = 52  # cards in the deck
        M = 4  # how many aces
        p = 5.0 / 52  # how many cards in a hand?
        self.fuzzrun = FuzzRun(N, M, p)

    def test_P_hit(self):
        self.assertAlmostEqual(self.fuzzrun.P_hit(), (1.0 / 54145))

    def test_P_miss(self):
        self.assertAlmostEqual(self.fuzzrun.P_miss(), (1 - (1.0 / 54145)))

    def test_ln_P(self):
        self.assertAlmostEqual(self.fuzzrun.ln_P(), math.log(1.0 / 54145))

    def test_lnfactorial(self):
        for x in range(1, 100):
            self.assertAlmostEqual(lnfactorial(x), math.log(math.factorial(x)))

    def test_shot_size(self):
        for N in range(5, 100000, 1000):
            for inv_p in range(2, 10002, 100):
                p = 1.0 / inv_p
                if (p * N > 1):
                    self.assertEqual(shot_size(N, p), int(math.floor(N * p)))

    def test_misses_until_quit(self):
        confidence = 0.5
        self.assertEqual(misses_until_quit(confidence, (1.0 / 54145)), 37531)

    def test_how_many_misses_until_quit(self):
        confidence = 0.5
        answer = int(math.ceil(math.log(1 - confidence) / math.log(1 - (1.0 / 54145))))
        self.assertEqual(self.fuzzrun.how_many_misses_until_quit(confidence), answer)

        # make sure we reject out-of-range values
        # 0.0 < confidence < 1.0
        self.assertRaises(AssertionError, self.fuzzrun.how_many_misses_until_quit, 1)
        self.assertRaises(AssertionError, self.fuzzrun.how_many_misses_until_quit, 0)

    def test_init(self):
        # N < M
        self.assertRaises(AssertionError, FuzzRun, 5, 10, 0.1)
        # 0.0 < p < 1.0
        self.assertRaises(AssertionError, FuzzRun, 52, 4, 0.0)
        self.assertRaises(AssertionError, FuzzRun, 52, 4, 1.0)

    def test_should_I_stop_yet(self):
        should_be_false = self.fuzzrun.how_many_misses_until_quit(0.5)
        for x in range(should_be_false):
            self.assertFalse(self.fuzzrun.should_I_stop_yet(x, 0.5))
        for x in range(should_be_false + 1, should_be_false + 1000):
            self.assertTrue(self.fuzzrun.should_I_stop_yet(x, 0.5))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
