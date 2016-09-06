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
from certfuzz.scoring.scorable_thing import ScorableThing, ScorableThingError

class Test(unittest.TestCase):

    def setUp(self):
        self.thing1 = ScorableThing()
        self.thing2 = ScorableThing(key='Thing2')

    def tearDown(self):
        pass

    def test_init(self):
        self.assertTrue(self.thing1.key.startswith('scorable_thing_'))
        self.assertEqual(self.thing2.key, 'Thing2')

        self.assertEqual(0, self.thing1.successes)
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0.5, self.thing1.probability)

    def test_repr(self):
        self.assertEqual(self.thing2.__repr__(), 'Thing2')

    def test_record_failure(self):
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        self.thing1.record_failure()
        self.assertEqual(1, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        # with tries as keyword
        self.thing1.record_failure(tries=3)
        self.assertEqual(4, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        # with tries, no keyword
        self.thing1.record_failure(32)
        self.assertEqual(36, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)

    def test_record_success(self):
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        self.thing1.record_success('a')
        self.assertEqual(1, self.thing1.tries)
        self.assertEqual(1, self.thing1.successes)
        # with tries as keyword
        self.thing1.record_success('b', tries=3)
        self.assertEqual(4, self.thing1.tries)
        self.assertEqual(2, self.thing1.successes)
        # with tries, no keyword
        self.thing1.record_success('c', 32)
        self.assertEqual(36, self.thing1.tries)
        self.assertEqual(3, self.thing1.successes)
        # repeat
        self.thing1.record_success('c')
        self.assertEqual(37, self.thing1.tries)
        self.assertEqual(3, self.thing1.successes)
        self.thing1.record_success('a', 3)
        self.assertEqual(40, self.thing1.tries)
        self.assertEqual(3, self.thing1.successes)

    def test_record_result(self):
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)
        self.thing1.record_result(successes=0, tries=0)
        self.assertEqual(0, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)

        self.thing1.record_result(successes=0, tries=1)
        self.assertEqual(1, self.thing1.tries)
        self.assertEqual(0, self.thing1.successes)

        self.thing1.record_result(successes=1, tries=1)
        self.assertEqual(2, self.thing1.tries)
        self.assertEqual(1, self.thing1.successes)

    def test_update(self):
        self.assertEqual(1, self.thing1.a)
        self.assertEqual(1, self.thing1.b)
        self.assertEqual(0.5, self.thing1.probability)
        self.thing1.update(1, 1)
        self.assertEqual(2, self.thing1.a)
        self.assertEqual(1, self.thing1.b)
        self.assertAlmostEqual(0.667, self.thing1.probability, places=3)
        self.thing1.update(1, 10)
        self.assertEqual(3, self.thing1.a)
        self.assertEqual(10, self.thing1.b)
        self.assertAlmostEqual(0.231, self.thing1.probability, places=3)

    def test_getstate_is_picklable(self):
        # getstate should return picklable thing
        import cPickle
        try:
            cPickle.dumps(self.thing1.__getstate__())
        except:
            self.fail('Unable to pickle __getstate__ result')

    def test_getstate_returns_dict(self):
        self.assertEqual(dict, type(self.thing1.__getstate__()))
        self.assertEqual(self.thing1.__getstate__(), self.thing1.__dict__)

    def test_to_json(self):
        try:
            self.assertEqual(str, type(self.thing1.to_json()))
        except Exception, e:
            self.fail('json.dumps failed: %s' % e)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
