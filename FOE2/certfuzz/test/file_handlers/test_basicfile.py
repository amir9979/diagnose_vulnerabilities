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
Created on Mar 23, 2011

@organization: cert.org
'''
import unittest
import tempfile
import os
from certfuzz.file_handlers.basicfile import BasicFile
import hashlib
import shutil

class Test(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.emptymd5 = hashlib.md5('').hexdigest()

        (fd1, self.f1) = tempfile.mkstemp(dir=self.tempdir)
        os.close(fd1)
        self.emptybasicfile = BasicFile(self.f1)

        (fd2, self.f2) = tempfile.mkstemp(dir=self.tempdir)
        self.content = "I'm here and I'm ready. They're not. Bring it."
        os.write(fd2, self.content)
        os.close(fd2)
        self.basicfile = BasicFile(self.f2)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_basicfile_init(self):
        self.assertEqual(self.emptybasicfile.md5, self.emptymd5)
        self.assertEqual(self.emptybasicfile.len, 0)
        self.assertEqual(self.emptybasicfile.bitlen, 0)
        self.assertEqual(self.basicfile.md5, 'b8a17b44dec164d67685a9fe9817da90')
        self.assertEqual(self.basicfile.len, len(self.content))
        self.assertEqual(self.basicfile.bitlen, 8 * len(self.content))

    def test_refresh(self):
        fd = open(self.emptybasicfile.path, 'w')
        fd.write('Boom, crush. Night, losers. Winning, duh. ')
        fd.close()

        self.assertEqual(self.emptybasicfile.md5, self.emptymd5)
        self.assertEqual(self.emptybasicfile.len, 0)
        self.assertEqual(self.emptybasicfile.bitlen, 0)
        self.emptybasicfile.refresh()
        self.assertEqual(self.emptybasicfile.md5, '0281570ea703d7e39dab89319fe96202')
        self.assertEqual(self.emptybasicfile.len, 42)
        self.assertEqual(self.emptybasicfile.bitlen, 8 * 42)

    def test_read(self):
        self.assertEqual(self.basicfile.read(), self.content)

        # nonexistent file should raise an exception
        os.remove(self.basicfile.path)
        self.assertFalse(os.path.exists(self.basicfile.path))
        self.assertRaises(Exception, self.basicfile.read)

    def test_exists(self):
        self.assertTrue(self.emptybasicfile.exists())
        self.assertTrue(self.basicfile.exists())
        os.remove(self.f1)
        self.assertFalse(self.emptybasicfile.exists())
        self.assertTrue(self.basicfile.exists())
        os.remove(self.f2)
        self.assertFalse(self.emptybasicfile.exists())
        self.assertFalse(self.basicfile.exists())

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_init']
    unittest.main()
