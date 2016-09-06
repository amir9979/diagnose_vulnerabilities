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
Created on Mar 23, 2012

@organization: cert.org
'''

import unittest
from certfuzz.campaign import campaign
from tempfile import mkstemp, mkdtemp
import yaml
import shutil
import os
import tempfile
from certfuzz.fuzztools import filetools

class Mock(object):
    def __getstate__(self):
        return dict(x=1, y=2, z=3)

class Test(unittest.TestCase):

    def _dump_test_config(self):
        cfg = {'campaign': {
                           'id': 'campaign_id',
                           'keep_heisenbugs': True,
                           'cached_state_file': mkstemp(dir=self.tmpdir)[1],
                           },
            'target': {
                'cmdline_template': 'cmdline_template',
                'program': self.program},
            'runoptions': {
                'first_iteration': 0,
                'last_iteration': 100,
                'seed_interval': 5,
                'keep_all_duplicates': True,
                'keep_unique_faddr': True},
            'directories': {
                'results_dir': mkdtemp(dir=self.tmpdir),
                'working_dir': mkdtemp(dir=self.tmpdir),
                'seedfile_dir': mkdtemp(dir=self.tmpdir)},
            'fuzzer': {
                'fuzzer': 'fuzzermodule'},
            'runner': {
                'runner': 'runnermodule'},
            'debugger': {
                'debugger': 'debuggermodule'}}
        self.cfg_file = mkstemp(dir=self.tmpdir)[1]
        with open(self.cfg_file, 'wb') as output:
            yaml.dump(cfg, stream=output)

    def setUp(self):
        self.tmpdir = mkdtemp()
        self.program = mkstemp(dir=self.tmpdir)[1]
        self._dump_test_config()
        self.campaign = campaign.Campaign(self.cfg_file)

        fd, f = tempfile.mkstemp()
        os.close(fd)
        os.remove(f)
        self.campaign.cached_state_file = f

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_init(self):
        self.assertEqual('%s.%s' % (campaign.packages['fuzzers'], 'fuzzermodule'),
                         self.campaign.fuzzer_module_name)
        self.assertEqual('%s.%s' % (campaign.packages['runners'], 'runnermodule'),
                         self.campaign.runner_module_name)
        self.assertEqual('%s.%s' % (campaign.packages['debuggers'], 'debuggermodule'),
                         self.campaign.debugger_module_name)

    def test_getstate(self):
        self.campaign.seedfile_set = Mock()

        # get_state should return a pickleable result
        state = self.campaign.__getstate__()

        import pickle
        try:
            pickle.dumps(state)
        except Exception, e:
            self.fail(e)

#    def test_to_json(self):
#        self.campaign.seedfile_set = Mock()
#
#        # make sure we can write
#        as_json = self.campaign.to_json()
#
#        pprint.pprint(as_json)
#        from_json = json.loads(as_json)
#
#        for k, v in self.campaign.__getstate__().iteritems():
#            self.assertTrue(k in from_json, '%s not found' % k)
#            if k == 'seedfile_set':
#                # make sure everything in the json version
#                # matches what was in our original sfs
#                sfs = from_json[k]
#                for k1, v1 in Mock().__getstate__().iteritems():
#                    self.assertTrue(k1 in sfs)
#                    self.assertEqual(sfs[k1], v1)
#            else:
#                self.assertEqual(from_json[k], v)

    def counter(self, *args):
        self.count += 1

    def test_save_state(self):

        # make sure we can write
        self.assertFalse(os.path.exists(self.campaign.cached_state_file))
        self.campaign._save_state()
        self.assertTrue(os.path.exists(self.campaign.cached_state_file))

#    @unittest.skip("JSON has been removed")
#    def test_read_state(self):
#        state = {'a': 1, 'b': 2, 'c': 3}
#        fd, f = tempfile.mkstemp(dir=self.tmpdir)
#        os.close(fd)
#        json.dump(state, open(f, 'wb'))
#
#        self.assertTrue(os.path.exists(f))
#        self.assertTrue(os.path.getsize(f) > 0)
#
#        self.count = 0
#        self.campaign.__setstate__ = self.counter
#        self.campaign._read_state(f)
#        self.assertEqual(self.count, 1)

    def test_set_state(self):
        state = {'crashes_seen': [1, 2, 3, 3],
                 'seedfile_set': {'things': {}},
                 'id': 2134,
                 'seed_dir_in': mkdtemp(dir=self.tmpdir),
                 'seed_dir_local': mkdtemp(dir=self.tmpdir),
                 'sf_set_out': tempfile.mktemp(dir=self.tmpdir)[1],
                 }
        self.campaign.__setstate__(state)
        self.assertEqual(self.campaign.crashes_seen, set([1, 2, 3]))

    def test_write_version(self):
        vf = os.path.join(self.campaign.outdir, 'version.txt')
        filetools.make_directories(self.campaign.outdir)
        self.assertTrue(os.path.isdir(self.campaign.outdir))
        self.assertFalse(os.path.exists(vf))
        self.campaign._write_version()
        self.assertTrue(os.path.exists(vf))
        self.assertTrue(os.path.getsize(vf) > 0)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
