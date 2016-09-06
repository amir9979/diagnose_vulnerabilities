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
from certfuzz.fuzztools.filetools import copy_file
from certfuzz.fuzztools.filetools import delete_files
from certfuzz.fuzztools.filetools import copy_files
from certfuzz.fuzztools.filetools import make_directories
from certfuzz.fuzztools.filetools import write_oneline_to_file
from certfuzz.fuzztools.filetools import get_file_md5
import hashlib
import shutil
from certfuzz.fuzztools import filetools
import unittest

class Test(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        try:
            shutil.rmtree(self.tempdir)
        except OSError:
            pass

    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def test_copy_file(self):
        (src_fd, src) = tempfile.mkstemp(text=True, dir=self.tempdir)
        (dummy, dst1) = tempfile.mkstemp(text=True, dir=self.tempdir)
        (dummy, dst2) = tempfile.mkstemp(text=True, dir=self.tempdir)

        # no need to keep the tmpfiles open
        os.close(src_fd)

        # remove the target files, since we'll
        # be copying to them in a sec
        for f in (dst1, dst2):
            os.remove(f)

        # make sure we're ready to test
        self.assertTrue(os.path.exists(src))
        for f in (dst1, dst2):
            self.assertFalse(os.path.exists(f))

        copy_file(src, dst1, dst2)

        # are the destinations there?
        for p in (src, dst1, dst2):
            self.assertTrue(os.path.exists(p))

        # ok, it worked. Now clean up after yourself

        for f in (src, dst1, dst2):
            self.delete_file(f)

    def test_delete_files(self):
        (f1_fd, f1) = tempfile.mkstemp(dir=self.tempdir, text=True)
        (f2_fd, f2) = tempfile.mkstemp(dir=self.tempdir, text=True)

        # no need to keep the tmpfiles open
        for f in (f1_fd, f2_fd):
            os.close(f)

        for f in (f1, f2):
            self.assertTrue(os.path.exists(f))

        delete_files(f1, f2)

        for f in (f1, f2):
            self.assertFalse(os.path.exists(f))

    def test_copy_files(self):
        d = tempfile.mkdtemp()
        (f1_fd, f1) = tempfile.mkstemp(dir=self.tempdir, text=True)
        (f2_fd, f2) = tempfile.mkstemp(dir=self.tempdir, text=True)

        # no need to keep the tmpfiles open
        for f in (f1_fd, f2_fd):
            os.close(f)

        # confirm the sources exist
        for p in (d, f1, f2):
            self.assertTrue(os.path.exists(p))

        dst_f1 = os.path.join(d, os.path.basename(f1))
        dst_f2 = os.path.join(d, os.path.basename(f2))

        # make sure they aren't already in dir
        for f in (dst_f1, dst_f2):
            self.assertFalse(os.path.exists(f))

        copy_files(d, f1, f2)

        # did they copy?
        for f in (dst_f1, dst_f2):
            self.assertTrue(os.path.exists(f))

        # clean up
        for f in (f1, f2, dst_f1, dst_f2):
            self.delete_file(f)

        os.removedirs(d)
        self.assertFalse(os.path.exists(d))

    def test_make_directories(self):
        d1 = tempfile.mkdtemp(dir=self.tempdir)
        d2 = tempfile.mkdtemp(dir=self.tempdir)

        # now that we have file names,
        # delete them so we can recreate them in our test
        for d in (d1, d2):
            os.removedirs(d)

        for d in (d1, d2):
            self.assertFalse(os.path.exists(d))

        make_directories(d1, d2)

        # they should be there now
        for d in (d1, d2):
            self.assertTrue(os.path.exists(d))
            self.assertTrue(os.path.isdir(d))

        # clean up
        for d in (d1, d2):
            os.removedirs(d)
            self.assertFalse(os.path.exists(d))

    def test_write_oneline_to_file(self):
        (fd, fpath) = tempfile.mkstemp(dir=self.tempdir, text=True)
        os.close(fd)

        line = "1234567890"
        write_oneline_to_file(line, fpath, 'w')

        self.assertTrue(os.path.exists(fpath))
        self.assertTrue(os.path.isfile(fpath))
        f = open(fpath, 'r').read()
        self.assertEqual(f.strip(), line)

        # clean up
        self.delete_file(fpath)

    def test_get_file_md5(self):
        (fd, f) = tempfile.mkstemp(dir=self.tempdir, text=True)

        self.assertEqual(get_file_md5(f), hashlib.md5('').hexdigest())
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        alphabet_hash = hashlib.md5(alphabet).hexdigest()
        os.write(fd, 'abcdefghijklmnopqrstuvwxyz')

        self.assertEqual(get_file_md5(f), alphabet_hash)

        os.close(fd)
        self.delete_file(f)

    def test_make_writable(self):
        (fd, f) = tempfile.mkstemp(dir=self.tempdir)
        os.chmod(f, 0444)
        self.assertFalse(os.access(f, os.W_OK))
        filetools.make_writable(f)
        self.assertTrue(os.access(f, os.W_OK))
        os.close(fd)

    def test_get_newpath(self):
        oldpath = '/path/to/foo.txt'
        newpath = filetools.get_newpath(oldpath, 'bar')
        self.assertEqual('/path/to/foobar.txt', newpath)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
