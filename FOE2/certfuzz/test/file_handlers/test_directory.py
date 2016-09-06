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
Created on Mar 18, 2011

@organization: cert.org
'''
import unittest
import tempfile
import os
import shutil
from certfuzz.file_handlers.directory import Directory, DirectoryError
import logging

logger = logging.getLogger(__name__)

class Test(unittest.TestCase):

    def setUp(self):
        self.path = tempfile.mkdtemp()
        self.assertTrue(os.path.isdir(self.path))
        # drop some files in the dir
        self.files = [os.path.join(self.path, filename) for filename in ('a', 'b', 'c')]
        [open(f, 'w') for f in self.files]
        self.directory = Directory(self.path)

    def tearDown(self):
        if os.path.isdir(self.path):
            shutil.rmtree(self.path)
        self.assertFalse(os.path.isdir(self.path))
        self.assertFalse(os.path.exists(self.path))

    def test_verify_dir(self):
        self.assertTrue(os.path.exists(self.path))
        self.assertTrue(os.path.isdir(self.path))
        # verify should fail if the dir doesn't exist
        shutil.rmtree(self.path)
        self.assertRaises(DirectoryError, self.directory._verify_dir)

        # verify should fail if the path is not a dir
        open(self.path, 'w')
        self.assertTrue(os.path.exists(self.path))
        self.assertFalse(os.path.isdir(self.path))
        self.assertRaises(DirectoryError, self.directory._verify_dir)

        # clean up
        os.remove(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_refresh(self):
        # make sure we got the files we created in setup
        for f in self.files:
            self.assertTrue(f in self.directory.paths())

        # create a new file, then test to see if it shows up in a refresh
        newfile = os.path.join(self.path, 'x')
        open(newfile, 'w').write('AAAA')

        self.assertFalse(newfile in self.directory.paths())
        self.directory.refresh()
        self.assertTrue(newfile in self.directory.paths())

    def test_symlinked_dir(self):
        # dir is symlink, link target exists but is not dir
        target_file = tempfile.mktemp()
        self.assertFalse(os.path.exists(target_file))
        open(target_file, 'w')
        self.assertTrue(os.path.exists(target_file))
        self.assertTrue(os.path.isfile(target_file))

        link_name = tempfile.mktemp()
        self.assertFalse(os.path.exists(link_name))
        os.symlink(target_file, link_name)
        self.assertTrue(os.path.exists(link_name))
        self.assertTrue(os.path.islink(link_name))
        self.assertTrue(os.path.isfile(link_name))

        self.assertRaises(DirectoryError, Directory, link_name)
        os.remove(link_name)
        os.remove(target_file)

        # dir is symlink, link target is dir
        target_dir = tempfile.mkdtemp()
        self.assertTrue(os.path.isdir(target_dir))
        link_name = tempfile.mktemp()
        self.assertFalse(os.path.exists(link_name))
        os.symlink(target_dir, link_name)
        self.assertTrue(os.path.exists(link_name))
        self.assertTrue(os.path.islink(link_name))
        self.assertTrue(os.path.isdir(link_name))

        d = Directory(link_name)
        self.assertEqual(link_name, d.dir)

        # remove the target dir - now we have a bad link
        os.rmdir(target_dir)
        self.assertFalse(os.path.exists(target_dir))

        # dir is symlink, link target does not exist
        self.assertTrue(os.path.islink(link_name))
        self.assertFalse(os.path.exists(os.readlink(link_name)))
        self.assertRaises(DirectoryError, Directory, link_name, True)

        os.remove(link_name)
        self.assertFalse(os.path.exists(link_name))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
