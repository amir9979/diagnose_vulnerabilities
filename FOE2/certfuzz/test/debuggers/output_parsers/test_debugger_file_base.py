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
Created on Jan 20, 2012

@organization: cert.org
'''

import unittest
import glob
import os
import logging
from certfuzz.debuggers.output_parsers import detect_format
from certfuzz.debuggers.output_parsers import UnknownDebuggerError

#logger = logging.getLogger()
#hdlr = logging.StreamHandler()
#logger.addHandler(hdlr)
#logger.setLevel(logging.WARNING)
#debuggers.debug_file.logger.setLevel(logging.DEBUG)

class Test(unittest.TestCase):

    def setUp(self):
        self.btdir = './backtraces'

        self.konqifiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, 'konqi*')]
        self.abrtfiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, 'abrt*')]
        self.gdbfiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, '*.gdb')]

        # files that look like gdb
        self.abrtgdbfiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, '_abrt*')]

        # files that are expected to raise an exception
        self.expect2fail = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, '*fail*')]

    def tearDown(self):
        pass

    def detect_format(self, filelist, expectedtype):
        for f in filelist:
            logger.debug('File: %s', f)
            try:
                detectedtype = detect_format(f)
                self.assertEqual(detectedtype, expectedtype, "File %s: expected: %s got: %s" % (f, expectedtype, detectedtype))
            except UnknownDebuggerError:
                print "Failed to recognize type for %s" % f

    def detect_format_fail(self, filelist):
        for f in filelist:
            self.assertRaises(UnknownDebuggerError, detect_format, f)

    def test_formats_that_should_succeed(self):
        self.detect_format(self.konqifiles, 'konqi')
        self.detect_format(self.gdbfiles, 'gdb')
        self.detect_format(self.abrtfiles, 'abrt')
        self.detect_format(self.abrtgdbfiles, 'gdb')

    def test_formats_that_should_fail(self):
        self.detect_format_fail(self.expect2fail)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
