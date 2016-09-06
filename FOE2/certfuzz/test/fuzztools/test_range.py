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
import unittest
from certfuzz.fuzztools.range import Range
import pprint
import json

class Test(unittest.TestCase):
    def setUp(self):
        self.r = Range(0, 1)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.r.max, 1.0)
        self.assertEqual(self.r.min, 0.0)
        self.assertEqual(self.r.mean, 0.5)
        self.assertEqual(self.r.span, 1.0)

    def test_repr(self):
        self.assertEqual(self.r.__repr__(), '0.000000-1.000000')

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
                self.assertEqual(state[k], v)

    def test_getstate(self):
        state = self.r.__getstate__()
        self.assertEqual(dict, type(state))
        print 'as dict...'
        pprint.pprint(state)

    def test_to_json(self):
        as_json = self.r.to_json(indent=4)

        print 'as JSON...'
        for l in as_json.splitlines():
            print l

        from_json = json.loads(as_json)

        # make sure we can round-trip it
        for k, v in self.r.__getstate__().iteritems():
            self.assertTrue(k in from_json)
            self.assertEqual(from_json[k], v)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
