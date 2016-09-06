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
from certfuzz.fuzztools.zzuflog import ZzufLog
'''
Created on Apr 8, 2011

@organization: cert.org
'''

import unittest

class Test(unittest.TestCase):
    def delete_file(self, f):
        if os.path.exists(f):
            os.remove(f)
        self.assertFalse(os.path.exists(f))

    def tearDown(self):
        self.delete_file(self.infile)
        self.delete_file(self.outfile)

    def setUp(self):
        (fd1, f1) = tempfile.mkstemp(text=True)
        os.close(fd1)
        self.infile = f1

        (fd2, f2) = tempfile.mkstemp(text=True)
        os.close(fd2)
        self.outfile = f2

        self.log = ZzufLog(self.infile, self.outfile)

    def test_get_last_line(self):
        open(self.infile, 'w')
        self.assertEqual(self.log._get_last_line(), '')

        (fd, f) = tempfile.mkstemp(text=True)
        os.write(fd, "firstline\n")
        os.write(fd, "secondline\n")
        os.write(fd, "thirdline\n")
        os.close(fd)

        log = ZzufLog(f, self.outfile)
        # log.line gets the result of _get_last_line before the infile is wiped out
        self.assertEqual(log.line, 'thirdline')
        self.delete_file(f)

    def test_set_exitcode(self):
        self.log.result = "blah"
        self.log._set_exitcode()
        self.assertEqual(self.log.exitcode, '')

        self.log.result = "exit 1701"
        self.log._set_exitcode()
        self.assertEqual(self.log.exitcode, 1701)

    def test_set_signal(self):
        self.log.result = "blah"
        self.log._set_signal()
        self.assertEqual(self.log.signal, '')

        self.log.result = "signal 17938"
        self.log._set_signal()
        self.assertEqual(self.log.signal, '17938')

    def test_parse_line(self):
        self.log.line = "blah"
        self.assertEqual(self.log._parse_line(), (False, False, ''))
        self.log.line = "zzuf[s=99,r=foo]: Welcome to Jurassic Park"
        self.assertEqual(self.log._parse_line(), (99, 'foo', 'Welcome to Jurassic Park'))

    def test_was_out_of_memory(self):
        # should be true
        self.log.result = "signal 15"
        self.assertTrue(self.log._was_out_of_memory())
        self.log.result = "exit 143"
        self.assertTrue(self.log._was_out_of_memory())

        # should be false
        self.log.result = "signal 8"
        self.assertFalse(self.log._was_out_of_memory())
        self.log.result = "exit 18"
        self.assertFalse(self.log._was_out_of_memory())

    def test_was_killed(self):
        # should be true
        self.log.result = "signal 9"
        self.assertTrue(self.log._was_killed())
        self.log.result = "exit 137"
        self.assertTrue(self.log._was_killed())

        # should be false
        self.log.result = "signal 8"
        self.assertFalse(self.log._was_killed())
        self.log.result = "exit 18"
        self.assertFalse(self.log._was_killed())

    def test_read_zzuf_log(self):
        (fd, f) = tempfile.mkstemp(text=True)
        line = "zzuf[s=%d,r=%s]: %s\n"
        os.write(fd, line % (10, "0.1-0.2", "foo"))
        os.write(fd, line % (85, "0.01-0.02", "bar"))
        os.close(fd)

        log = ZzufLog(f, self.outfile)

        self.assertEqual(log.seed, 85)
        self.assertEqual(log.range, "0.01-0.02")
        self.assertEqual(log.result, "bar")
        self.assertEqual(log.line, (line % (85, "0.01-0.02", "bar")).strip())

        # cleanup
        self.delete_file(f)

    def test_crash_logged(self):
        self.log.result = "a"
        self.log._set_exitcode()
        self.assertFalse(self.log.crash_logged(False))

        # _was_killed => true
        # should be false
        self.log.result = "signal 9"
        self.log._set_exitcode()
        self.assertFalse(self.log.crash_logged(False))

        # _was_out_of_memory => true
        # should be false
        self.log.result = "signal 15"
        self.log._set_exitcode()
        self.assertFalse(self.log.crash_logged(False))

        # should be false since infile is empty
        self.log.result = "a"
        self.log._set_exitcode()
        self.assertFalse(self.log.parsed)
        self.assertFalse(self.log.crash_logged(False))

        # should be true
        self.log.result = "a"
        self.log._set_exitcode()
        self.log.parsed = True # have to fake it since infile is empty
        self.assertTrue(self.log.crash_logged(False))

#    def test_crash_exit(self):
#        crash_exit_code_list = [77, 88, 99]
#
#        self.log.result = "exit 77"
#        self.log._set_exitcode()
#        self.assertTrue(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 88"
#        self.log._set_exitcode()
#        self.assertTrue(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 99"
#        self.log._set_exitcode()
#        self.assertTrue(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 1"
#        self.log._set_exitcode()
#        self.assertFalse(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 2"
#        self.log._set_exitcode()
#        self.assertFalse(self.log._crash_exit(crash_exit_code_list))
#
#        self.log.result = "exit 3"
#        self.log._set_exitcode()
#        self.assertFalse(self.log._crash_exit(crash_exit_code_list))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
