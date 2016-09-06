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

from certfuzz.fuzztools.zzuf import Zzuf
from certfuzz.fuzztools.zzuf import ZzufTestCase
import re
'''
Created on Apr 8, 2011

@organization: cert.org
'''

import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.z = Zzuf('a', 1, 2, 'd', 'e', 'f',
                      True,
                      0.01,
                      0.1,
                      100
                      )
        pass

    def tearDown(self):
        pass

    def test_testcase_set_cmdline(self):
        expected = "cat a | zzuf -sb -rc > d"
        testcase = ZzufTestCase('a', 'b', 'c', 'd')
        self.assertEqual(testcase.cmdline, expected)

    def test_generate_test_case(self):
        # can not test without real data
        # see test_testcase_set_cmdline()
        pass

    def test_get_go_fuzz_cmdline(self):
        self.z.dir = 'dir'
        self.z.zzuf_args = 'args'
        self.z.get_command = 'get_command'
        self.z.file = 'file'
        expected = "cd dir && zzuf args d 2> file"
        self.assertEqual(self.z._get_go_fuzz_cmdline(), expected)

    def test_go_fuzz(self):
        # cannot test nondestructively
        # see test_get_go_fuzz_cmdline()
        pass

    def test_get_zzuf_args(self):

        zzuf_args = self.z._get_zzuf_args()

        splitparts = lambda L: [re.sub('^--', '', s) for s in L.split(' ')]

        # strip out the leading '--' from args to make it easier to verify
        parts = splitparts(zzuf_args)

        [self.assertTrue(s in parts, s) for s in ('signal', 'quiet')]
        self.assertTrue('max-crashes=1' in parts)
        self.assertTrue('opmode=copy' in parts)

        # check for presence of ratiomin and ratiomax
        ratio_item = [x for x in parts if "ratio" in x].pop()
        ratio_item = ratio_item.split('=')[1]  # take the part after the equals sign
        (rmin, rmax) = ratio_item.split(':')
        self.assertEqual(float(rmin), 0.01)
        self.assertEqual(float(rmax), 0.1)

        # TODO check for presence of timeout
        max_usertime_item = [x for x in parts if "usertime" in x].pop()
        max_usertime = max_usertime_item.split('=')[1]
        self.assertEqual(float(max_usertime), 100.00)

        # call _get_zzuf_args() again with copymode=False
        self.z.copymode = False
        zzuf_args = self.z._get_zzuf_args()

        # strip out the leading '--' from args to make it easier to verify
        parts = splitparts(zzuf_args)

        self.assertFalse('check-exit' in parts)
        self.assertFalse('opmode=copy' in parts)

        # check case where quiet is False
        self.z.quiet = False
        # strip out the leading '--' from args to make it easier to verify
        parts = splitparts(self.z._get_zzuf_args())
        self.assertFalse('quiet' in parts)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
