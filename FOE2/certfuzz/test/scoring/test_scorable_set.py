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
Created on Mar 26, 2012

@organization: cert.org
'''

import unittest
import random
import tempfile

from certfuzz.scoring.scorable_set import ScorableSet2, ScorableSetError, \
    EmptySetError
from certfuzz.helpers import random_str
import os
import shutil
import csv

class MockScorableThing(object):
    def __init__(self):
        self.key = random_str(8)
        self.probability = random.uniform(0.0, 1.0)

class Test(unittest.TestCase):

    def setUp(self):
        self.ss = ScorableSet2()
        self.things = []
        self.tmpdir = tempfile.mkdtemp()
        fd, f = tempfile.mkstemp(dir=self.tmpdir)
        os.close(fd)
        os.remove(f)
        self.tmpfile = f

        for _x in xrange(5):
            thing = MockScorableThing()
            self.ss.add_item(thing.key, thing)
            self.things.append(thing)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_scaled_score(self):
        self.ss._update_probabilities()
        score_sum = sum([x for x in self.ss.scaled_score.itervalues()])
        self.assertAlmostEqual(score_sum, 1.0)

    def test_del_item(self):
        # progressively delete all the things and make sure they go away
        # as expected
        while self.things:
            n_before = len(self.things)
            self.assertEqual(len(self.ss.things), n_before)
            thing_to_del = self.things.pop()
            self.ss.del_item(thing_to_del.key)
            n_after = n_before - 1
            self.assertEqual(len(self.things), n_after)
            self.assertEqual(len(self.ss.things), n_after)

    def test_add_item(self):
        ss = ScorableSet2()
        for _x in xrange(100):
            thing = MockScorableThing()
            self.assertEqual(len(ss.things), _x)
            ss.add_item(thing.key, thing)
            self.assertEqual(len(ss.things), _x + 1)
            self.assertTrue(thing.key in ss.things)
            self.assertTrue(thing in ss.things.values())

    def test_empty_set(self):
        ss = ScorableSet2()
        self.assertEqual(0, len(ss.things))
        self.assertRaises(EmptySetError, ss.next_key)
        self.assertRaises(EmptySetError, ss.next_item)

    def test_read_csv(self):
        self.assertRaises(ScorableSetError, self.ss._read_csv)

        self.ss.datafile = self.tmpfile
        d = {'x': 1, 'y': 2, 'z': 3}
        keys = list(d.keys())

        with open(self.ss.datafile, 'wb') as datafile:
            writer = csv.writer(datafile)
            writer.writerow(keys)
            row = [d[k] for k in keys]
            writer.writerow(row)

        read_csv = self.ss._read_csv()
        d_out = read_csv.pop(0)
        for k in keys:
            self.assertTrue(k in d_out)
            self.assertEqual(d[k], int(d_out[k]))

    def test_update_csv(self):
        self.ss._update_probabilities()
        # raise error if datafile is undefined
        self.assertRaises(ScorableSetError, self.ss.update_csv)

        self.ss.datafile = self.tmpfile
        self.assertFalse(os.path.exists(self.tmpfile))

        # make sure it can create a file from scratch
        self.ss.update_csv()
        self.assertTrue(os.path.exists(self.tmpfile))
        with open(self.ss.datafile, 'rb') as f:
            data = list(csv.DictReader(f))

        self.assertEqual(len(data), 1)
        for row in data:
            for k in self.ss.things.keys():
                self.assertTrue(k in row)

        # make sure it adds a second row
        self.ss.update_csv()
        with open(self.ss.datafile, 'rb') as f:
            data = list(csv.DictReader(f))

        self.assertEqual(len(data), 2)
        for row in data:
            for k in self.ss.things.keys():
                self.assertTrue(k in row)

        self.ss.update_csv()
        # we should be at 4 lines total now (1 header, 3 data)
        with open(self.ss.datafile, 'rb') as f:
            self.assertEqual(len(f.readlines()), 4)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
