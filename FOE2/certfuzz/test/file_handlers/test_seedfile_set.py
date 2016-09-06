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
Created on Apr 14, 2011

@organization: cert.org
'''
import unittest
import logging
import tempfile
import os
import shutil
from pprint import pprint

from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.file_handlers.directory import Directory
from certfuzz.file_handlers.seedfile import SeedFile
import hashlib
from certfuzz.scoring.scorable_set import EmptySetError
#from pprint import pprint

class Test(unittest.TestCase):

    def setUp(self):
        campaign_id = 'testcampaign'

        self.origindir = tempfile.mkdtemp()
        self.localdir = tempfile.mkdtemp()
        self.outputdir = tempfile.mkdtemp()

        # create some files
        self.file_count = 5
        self.files = []
        for i in range(self.file_count):
            (fd, f) = tempfile.mkstemp(dir=self.origindir)

            os.write(fd, 'abacab%d' % i)
            os.close(fd)
            self.files.append(f)

        # create a set
        self.sfs = SeedfileSet(campaign_id, self.origindir, self.localdir, self.outputdir)

    def tearDown(self):
        for f in self.files:
            os.remove(f)
            self.assertFalse(os.path.exists(f))
        for d in (self.origindir, self.localdir, self.outputdir):
            shutil.rmtree(d)
            self.assertFalse(os.path.exists(d))

    def test_pickle(self):
        import pickle
        self.assertTrue(hasattr(self.sfs, 'things'))
        # no files added yet
        self.assertEqual(0, len(self.sfs.things))
        # add the files
        self.sfs._setup()
        # confirm that the files are there
        self.assertEqual(self.file_count, len(self.sfs.things))
        unpickled = pickle.loads(pickle.dumps(self.sfs))
        pprint(unpickled.__dict__)

    def test_set_directories(self):
        self.assertEqual(self.sfs.originpath, self.origindir)
        self.assertEqual(self.sfs.localpath, self.localdir)
        self.assertEqual(self.sfs.outputpath, self.outputdir)
        self.assertEqual(None, self.sfs.origindir)
        self.assertEqual(None, self.sfs.localdir)
        self.assertEqual(None, self.sfs.outputdir)

        self.sfs._set_directories()

        self.assertEqual(Directory, self.sfs.origindir.__class__)
        self.assertEqual(Directory, self.sfs.localdir.__class__)
        self.assertEqual(Directory, self.sfs.outputdir.__class__)

        # make sure the file(s) we created in setUp are in origindir
        self.assertEqual(self.file_count, len(self.sfs.origindir.files))

    def test_copy_files_to_localdir(self):
        # mock the things
        self.sfs.origindir = [1, 2, 3, 4, 5]
        copied = []
        self.sfs.copy_file_from_origin = lambda x: copied.append(x)
        # do the test
        self.sfs._copy_files_to_localdir()
        self.assertEqual(self.sfs.origindir, copied)

    def test_copy_file_from_origin(self):
        pass

    def test_add_local_files_to_set(self):
        pass

    def test_add_file(self):
        self.assertNotEqual(0, len(self.files))
        self.assertEqual(0, len(self.sfs.things))
        self.sfs.add_file(*self.files)
        self.assertEqual(5, len(self.sfs.things))
        for thing in self.sfs.things.itervalues():
            self.assertEqual(SeedFile, thing.__class__)

    def test_init(self):
        self.assertEqual(self.outputdir, self.sfs.seedfile_output_base_dir)
        self.assertEqual(0, len(self.sfs.things))

    def test_getstate_is_pickle_friendly(self):
        # getstate should return a pickleable object
        import pickle
        state = self.sfs.__getstate__()
        try:
            pickle.dumps(state)
        except Exception, e:
            self.fail('Failed to pickle state: %s' % e)

    def test_getstate(self):
        state = self.sfs.__getstate__()
        self.assertEqual(dict, type(state))

        for k, v in self.sfs.__dict__.iteritems():
            # make sure we're deleting what we need to
            if k in ['localdir', 'origindir', 'outputdir']:
                self.assertFalse(k in state)
            else:
                self.assertTrue(k in state, '%s not found' % k)

    def test_setstate(self):
        self.sfs.__enter__()
        state_before = self.sfs.__getstate__()
        self.sfs.__setstate__(state_before)
        self.assertEqual(self.file_count, self.sfs.sfcount)
        state_after = self.sfs.__getstate__()

        for k, v in state_before.iteritems():
            self.assertTrue(k in state_after)
            if not k == 'things':
                self.assertEqual(v, state_after[k])

        for k, thing in state_before['things'].iteritems():
            # is there a corresponding thing in sfs?
            self.assertTrue(k in self.sfs.things)

            for x, y in thing.iteritems():
                # was it set correctly?
                self.assertEqual(thing[x], self.sfs.things[k].__dict__[x])

        self.assertEqual(self.file_count, self.sfs.sfcount)

    def test_setstate_with_changed_files(self):
        # refresh the sfs
        self.sfs.__enter__()

        # get the original state
        state_before = self.sfs.__getstate__()
        self.assertEqual(len(state_before['things']), self.file_count)

        # delete one of the files
        file_to_remove = self.files.pop()
        localfile_md5 = hashlib.md5(open(file_to_remove, 'rb').read()).hexdigest()
        localfilename = "sf_%s" % localfile_md5

        # remove it from origin
        os.remove(file_to_remove)
        self.assertFalse(file_to_remove in self.files)
        self.assertFalse(os.path.exists(file_to_remove))
#        print "removed %s" % file_to_remove

#        # remove it from localdir
        localfile_to_remove = os.path.join(self.localdir, localfilename)
        os.remove(localfile_to_remove)
        self.assertFalse(os.path.exists(localfile_to_remove))

        # create a new sfs
        new_sfs = SeedfileSet()
        new_sfs.__setstate__(state_before)

        self.assertEqual(len(new_sfs.things), (self.file_count - 1))

#        print "Newthings: %s" % new_sfs.things.keys()
        for k, thing in state_before['things'].iteritems():
#            print "k: %s" % k
            if k == localfile_md5:
                self.assertFalse(k in new_sfs.things)
                continue
            else:
                # is there a corresponding thing in sfs?
                self.assertTrue(k in new_sfs.things)

            for x, y in thing.iteritems():
                # was it set correctly?
                sfsthing = new_sfs.things[k].__dict__[x]
                if hasattr(sfsthing, '__dict__'):
                    # some things are complex objects themselves
                    # so we have to compare their __dict__ versions
                    self._same_dict(y, sfsthing.__dict__)
                else:
                    # others are just simple objects and we can
                    # compare them directly
                    self.assertEqual(y, sfsthing)

        self.assertEqual(self.file_count - 1, new_sfs.sfcount)

    def _same_dict(self, d1, d2):
        for k, v in d1.iteritems():
#            print k
            self.assertTrue(k in d2)
            if not v == d2[k]:
                pprint(v)
                pprint(d2[k])

            self.assertEqual(v, d2[k])

    def test_next_item(self):
        self.assertEqual(0, len(self.sfs.things))
        self.assertRaises(EmptySetError, self.sfs.next_key)
        self.assertRaises(EmptySetError, self.sfs.next_item)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
