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
Created on Apr 2, 2012

@organization: cert.org
'''
import unittest
from certfuzz.campaign.config.foe_config import Config
import os
import yaml
import tempfile
import shutil
#import pprint
from certfuzz.campaign.config import ConfigError
import logging

logger = logging.getLogger()
hdlr = logging.FileHandler(os.devnull)
logger.addHandler(hdlr)

class Test(unittest.TestCase):

    def _get_minimal_config(self):
        self.cfg_in = {'target': {'cmdline_template': '',
                                  'program': ''},
                       'runoptions': {}}
        fd, f = tempfile.mkstemp(suffix='.yaml', dir=self.tempdir, text=True)
        os.close(fd)
        with open(f, 'w') as fd:
            yaml.dump(self.cfg_in, fd)

        return Config(f)

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_empty_cfg_raises_exception(self):
        self.cfg_in = {}
        fd, f = tempfile.mkstemp(suffix='.yaml', dir=self.tempdir, text=True)
        os.close(fd)
        with open(f, 'w') as fd:
            yaml.dump(self.cfg_in, fd)

        self.assertRaises(KeyError, Config, f)

    def test_minimal_config(self):
        try:
            c = self._get_minimal_config()
        except Exception, e:
            self.fail('Exception on _get_minimal_config: %s' % e)

        self.assertTrue(c)

    def test_debugger_timeout_exceeds_runner(self):
        c = self._get_minimal_config()
        import itertools

        # no runner
        c.config.update({'runner': {'runner': None},
                         'debugger': {'runtimeout': 37}})
        c.validate()
        self.assertEqual(37, c.config['debugger']['runtimeout'])

        for (a, b) in itertools.product(range(10), range(10)):
            c.config.update({'runner': {'runner': 'foo', 'runtimeout': a},
                             'debugger': {'runtimeout': b}})
            self.assertEqual(a, c.config['runner']['runtimeout'])
            self.assertEqual(b, c.config['debugger']['runtimeout'])

            if a == 0 or b == 0:
                self.assertRaises(ConfigError, c.validate)
                continue
            c.validate()
            self.assertEqual(a, c.config['runner']['runtimeout'])
            expected = max(b, (2 * a))
            self.assertEqual(expected, c.config['debugger']['runtimeout'])

    def _counter(self):
        self.counter += 1

    def test_validation(self):
        c = self._get_minimal_config()
        self.counter = 0
        c.validations = [self._counter]
        for dummy in range(10):
            c.validate()
        self.assertEqual(10, self.counter)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
