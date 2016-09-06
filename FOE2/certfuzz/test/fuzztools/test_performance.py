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

from certfuzz.fuzztools.performance import TimeStamper
import itertools

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.ts = TimeStamper()
        self.ts.start = 100.0
        self.ts.timestamps = [(101.0, 'a'), (104.14, 'b')]

    def tearDown(self):
        pass

    def test_timestamp(self):
        l = len(self.ts.timestamps)
        self.ts.timestamp('foo')
        self.assertEqual(len(self.ts.timestamps), l + 1)

    def test_get_timestamps(self):
        timestamps = self.ts.get_timestamps()
        self.assertEqual(len(timestamps), 2)
        self.assertAlmostEqual(timestamps[-1] - timestamps[0], 3.14, 2)

    def test_relative_to_start(self):
        [self.assertAlmostEqual(x, y) for (x, y) in itertools.izip(self.ts.relative_to_start(), (1.0, 4.14))]

    def test_deltas(self):
        self.ts.timestamps.append((106.0, 'c'))
        [self.assertAlmostEqual(x, y) for (x, y) in itertools.izip(self.ts.deltas(), (3.14, 1.86))]

    def test_delta_stats(self):
        self.ts.timestamps = [(4, 'a'), (5, 'b'), (7, 'c'), (8, 'd'), (9, 'e'), (12, 'f')]
        self.assertEqual(self.ts.delta_stats(), (1.6, 0.8))

    def test_last_ts(self):
        self.assertEqual(self.ts.last_ts(), 104.14)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
