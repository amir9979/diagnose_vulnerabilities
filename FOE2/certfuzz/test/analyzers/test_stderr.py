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

import os
import tempfile
from certfuzz.analyzers.stderr import StdErr

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
import sys

class Mock(object):
    pass

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)
        self.delete_file(f)
        self.file = '%s.stderr' % f

        cfg = Mock()
        cfg.progtimeout = 1
        if sys.platform == 'win32':
            cfg.get_command_list = lambda x: ['c:\\cygwin\\bin\\cat.exe', '-a', 'foo']
        else:
            cfg.get_command_list = lambda x: ['cat', '-a', 'foo']

        crash = Mock()
        crash.fuzzedfile = Mock()
        crash.fuzzedfile.path = f
        crash.fuzzedfile.dirname = os.path.dirname(f)
        crash.killprocname = 'bar'

        self.se = StdErr(cfg, crash)

    def tearDown(self):
        if os.path.exists(self.file):
            self.delete_file(self.file)
        if os.path.exists(self.se.outfile):
            self.delete_file(self.se.outfile)

    def test_get_stderr(self):
        self.assertFalse(os.path.exists(self.file))
        self.se.go()
        self.assertTrue(os.path.exists(self.file))
        contents = open(self.file, 'r').read()
        self.assertTrue(len(contents) > 0)
        self.assertTrue('option' in contents)
        self.assertTrue('cat' in contents)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
