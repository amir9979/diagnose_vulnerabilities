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
import unittest
import os
import ConfigParser
from certfuzz.campaign.config.bff_config import ConfigHelper
from certfuzz.campaign.config.bff_config import MINIMIZED_EXT
from certfuzz.campaign.config.bff_config import KILL_SCRIPT
import tempfile
from certfuzz.campaign.config.bff_config import read_config_options

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        # build a config
        self.config = ConfigParser.RawConfigParser()

        self.config.add_section("campaign")
        self.config.set('campaign', 'id', 'campaign_id')
        self.config.set('campaign', 'distributed', 'False')

        self.config.add_section("directories")
        self.config.set('directories', 'remote_dir', 'remote_dir')
        self.config.set('directories', 'crashers_dir', 'crashers_dir')
        self.config.set('directories', 'seedfile_origin_dir', 'seedfile_origin_dir')

        self.config.set('directories', 'output_dir', 'output_dir')
        self.config.set('directories', 'local_dir', 'local_dir')
        self.config.set('directories', 'seedfile_output_dir', 'seedfile_output_dir')
        self.config.set('directories', 'seedfile_local_dir', 'seedfile_local_dir')
        self.config.set('directories', 'cached_objects_dir', 'cached_objects_dir')
        self.config.set('directories', 'temp_working_dir', 'temp_working_dir')
        self.config.set('directories', 'watchdog_file', 'watchdog_file')
        self.config.set('directories', 'debugger_template_dir', 'debugger_template_dir')

        self.config.add_section("target")
        self.config.set('target', 'cmdline', '/path/to/program $SEEDFILE outfile.ext')
        self.config.set('target', 'killprocname', '/path/to/killprocname')

        self.config.add_section('timeouts')
        self.config.set('timeouts', 'killproctimeout', '1')
        self.config.set('timeouts', 'watchdogtimeout', '2')
        self.config.set('timeouts', 'debugger_timeout', '4')
        self.config.set('timeouts', 'progtimeout', '3.4')
        self.config.set('timeouts', 'valgrindtimeout', '6')
        self.config.set('timeouts', 'minimizertimeout', '6')

        self.config.add_section('zzuf')
        self.config.set('zzuf', 'copymode', '1')
        self.config.set('zzuf', 'ratiomin', '0.0001')
        self.config.set('zzuf', 'ratiomax', '0.01')
        self.config.set('zzuf', 'start_seed', '1000')
        self.config.set('zzuf', 'seed_interval', '500')
        self.config.set('zzuf', 'max_seed', '100000')

        self.config.add_section('verifier')
        self.config.set('verifier', 'backtracelevels', '17')
        self.config.set('verifier', 'minimizecrashers', '1')
        self.config.set('verifier', 'manualcutoff', '10')
#        self.config.set('verifier', 'keepduplicates', '1')
        self.config.set('verifier', 'minimize_to_string', '1')
        self.config.set('verifier', 'use_valgrind', '1')

        # create a ConfigHelper object
        self.cfg = ConfigHelper(self.config)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.cfg.killprocname, 'killprocname')
        self.assertEqual(self.cfg.killproctimeout, 1)
        self.assertEqual(self.cfg.watchdogtimeout, 2)
        self.assertEqual(self.cfg.copymode, 1)
        self.assertEqual(self.cfg.progtimeout, 3.4)
        self.assertEqual(self.cfg.seedfile_local_dir, 'seedfile_local_dir')
        self.assertEqual(self.cfg.output_dir, 'output_dir')
        self.assertEqual(self.cfg.local_dir, 'local_dir')
        self.assertEqual(self.cfg.debugger_timeout, 4)
        self.assertEqual(self.cfg.backtracelevels, 17)
        self.assertEqual(self.cfg.minimizecrashers, 1)
        self.assertEqual(self.cfg.valgrindtimeout, 6)

    def test_program_is_script(self):
        pass

    def test_check_program_file_type(self):
        f = os.path.abspath(__file__)
        if f.endswith('pyc'):
            # trim the last char ('c')
            f = f[:-1]
        self.cfg.program = f
        print f
        self.assertTrue(self.cfg.program_is_script())

    def test_get_minimized_file(self):
        self.assertEqual(self.cfg.get_minimized_file('foo.txt'), 'foo-%s.txt' % MINIMIZED_EXT)

    def test_get_killscript_path(self):
        self.assertEqual(self.cfg.get_killscript_path('foo'), os.path.join('foo', '%s') % KILL_SCRIPT)

    def test_uniquelog(self):
        self.assertEqual(self.cfg.uniq_log, os.path.join('output_dir', 'uniquelog.txt'))

    def test_crashexitcodesfile(self):
        self.assertEqual(self.cfg.crashexitcodesfile, os.path.join('local_dir', 'crashexitcodes'))

    def test_zzuf_log_file(self):
        self.assertEqual(self.cfg.zzuf_log_file, os.path.join('local_dir', 'zzuf_log.txt'))

    def test_zzuf_log_out(self):
        self.assertEqual(self.cfg.zzuf_log_out('seedfile'), os.path.join('seedfile', 'zzuf_log.txt'))

    def test_read_config_options(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)

        with open(f, 'wb') as configfile:
            self.config.write(configfile)

        cfg = read_config_options(f)

        self.assertEqual(cfg.killprocname, 'killprocname')
        self.assertEqual(cfg.killproctimeout, 1)
        self.assertEqual(cfg.watchdogtimeout, 2)
        self.assertEqual(cfg.copymode, 1)
        self.assertEqual(cfg.progtimeout, 3.4)
        self.assertEqual(cfg.seedfile_local_dir, 'seedfile_local_dir')
        self.assertEqual(cfg.output_dir, 'output_dir')
        self.assertEqual(cfg.local_dir, 'local_dir')
        self.assertEqual(cfg.debugger_timeout, 4)
        self.assertEqual(cfg.backtracelevels, 17)
        self.assertEqual(cfg.minimizecrashers, 1)
        self.assertEqual(cfg.valgrindtimeout, 6)

        self.delete_file(f)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
