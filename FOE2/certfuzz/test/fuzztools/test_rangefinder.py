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
import json
import unittest

from certfuzz.fuzztools.rangefinder import RangeFinder

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        self.min = 0.001
        self.max = 0.999
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)
        self.tmpfile = f
        self.r = RangeFinder(self.min, self.max, self.tmpfile)

    def tearDown(self):
        self.delete_file(self.tmpfile)

    def test_get_ranges(self):
        ranges = self._ranges()

        # the high end of the last range should be the max
        self.assertAlmostEqual(ranges[-1].max, self.max)

        # the low end of the first range should be the min
        self.assertAlmostEqual(ranges[0].min, self.min)

        # make sure the internal ranges match up
        for (this, next_element) in zip(ranges[:-1], ranges[1:]):
            self.assertEqual(this.max, next_element.min)

        # Ranges would be 0.375-0.601, 0.601-0.981, 0.981-0.999
        # if it weren't for the fix that merges the last two
        # so we should only see two ranges
        r = RangeFinder(0.375, 0.999, self.tmpfile)
        self.assertEqual(len(r.things), 2)
        ranges = [v for (dummy, v) in sorted(r.things.items())]
        self.assertAlmostEqual(ranges[0].min, 0.375)
        self.assertAlmostEqual(ranges[1].max, 0.999)

    def _ranges(self):
        keys = sorted(self.r.things.keys())
        return [self.r.things[k] for k in keys]

    def test_range_orderings(self):
        # first term should be smaller than second term
        ranges = self.r.things.values()
        [self.assertTrue(x.min <= x.max) for x in ranges]

    def test_range_overlaps(self):
        # this one's min should be the next_element one's max
        ranges = self._ranges()
        [self.assertEqual(x.min, y.max) for (x, y) in zip(ranges[1:], ranges[:-1])]

    def test_range_mean(self):
        # mean should be halfway between min and max
        [self.assertAlmostEqual(x.mean, ((x.max + x.min) / 2)) for x in self.r.things.values()]

    def test_getstate_is_pickle_friendly(self):
        # getstate should return a pickleable object
        import pickle
        state = self.r.__getstate__()
        try:
            pickle.dumps(state)
        except Exception, e:
            self.fail('Failed to pickle state: %s' % e)

    def test_getstate_has_all_expected_items(self):
        state = self.r.__getstate__()
        for k, v in self.r.__dict__.iteritems():
            # make sure we're deleting what we need to
            if k in ['logger']:
                self.assertFalse(k in state)
            else:
                self.assertTrue(k in state, '%s not found' % k)
                self.assertEqual(type(state[k]), type(v))

    def test_getstate(self):
        state = self.r.__getstate__()
        self.assertEqual(dict, type(state))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
