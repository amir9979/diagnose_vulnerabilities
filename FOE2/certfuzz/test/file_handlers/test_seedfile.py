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
Created on Apr 15, 2011

@organization: cert.org
'''

import unittest
import tempfile
import os
from certfuzz.file_handlers.seedfile import SeedFile
from pprint import pprint
from certfuzz.fuzztools.rangefinder import RangeFinder

class Test(unittest.TestCase):

    def setUp(self):
        (fd, self.file) = tempfile.mkstemp()
        self.dir = tempfile.mkdtemp()
        self.content = "I'm here and I'm ready. They're not. Bring it."
        os.write(fd, self.content)
        os.close(fd)
        self.sf = SeedFile(self.dir, self.file)

    def tearDown(self):
        os.remove(self.file)
        assert not os.path.exists(self.file)

    def test_init(self):
        self.assertEqual(self.sf.output_dir, os.path.join(self.dir, self.sf.md5))

    def test_record_hit(self):
        self.assertEqual(0, self.sf.successes)
        self.assertFalse('x' in self.sf.seen)
        self.sf.record_success('x')
        self.assertEqual(1, self.sf.successes)
        self.assertTrue('x' in self.sf.seen)

    def test_getstate(self):
        self.assertEqual(RangeFinder, type(self.sf.rangefinder))
        state = self.sf.__getstate__()
        self.assertEqual(dict, type(state))
        self.assertEqual(dict, type(state['rangefinder']))

    def test_setstate(self):
        state = self.sf.__getstate__()

        self.assertEqual(0, self.sf.tries)
        self.assertEqual(0, state['tries'])

        # can we change something?
        state['tries'] = 1000
        self.sf.__setstate__(state)
        self.assertEqual(1000, self.sf.tries)
        # make sure we restore rangefinder
        self.assertEqual(RangeFinder, type(self.sf.rangefinder))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
