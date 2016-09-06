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
Created on Oct 11, 2012

@organization: cert.org
'''
import logging
import os
import tempfile

from .. import __version__
from ..fuzztools import hamming, filetools
from ..file_handlers.basicfile import BasicFile

logger = logging.getLogger(__name__)

class CrashError(Exception):
    pass

class Crash(object):
    tmpdir_pfx = 'crash-'

    def __init__(self, seedfile, fuzzedfile, dbg_timeout):
        logger.debug('Inititalize Crash')

        self.seedfile = seedfile
        self.fuzzedfile = fuzzedfile

        self.debugger_timeout = dbg_timeout

        self.debugger_template = None
        # All crashes are heisenbugs until proven otherwise
        self.is_heisenbug = True

        # Exploitability is HEISENBUG unless proven otherwise
        self.exp = 'HEISENBUG'

        self.workdir_base = tempfile.gettempdir()

        # set some defaults
        # Not a crash until we're sure
        self.is_crash = False
        self.debugger_file = None
        self.is_unique = False
        self.is_corrupt_stack = False
        self.copy_fuzzedfile = True
        self.hd_bits = None
        self.hd_bytes = None
        self.pc = None
        self.signature = None
        self.logger = None
        self.result_dir = None
        self.debugger_missed_stack_corruption = False
        self.total_stack_corruption = False
        self.pc_in_function = False

#    def __repr__(self):
#        pass

#    def __str__(self):
#        pass

    def _create_workdir_base(self):
        # make sure the workdir_base exists
        if not os.path.exists(self.workdir_base):
            filetools.make_directories(self.workdir_base)

    def __enter__(self):
        self._create_workdir_base()
        self.update_crash_details()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _get_output_dir(self, *args):
        raise NotImplementedError

    def _rename_dbg_file(self):
        raise NotImplementedError

    def _rename_fuzzed_file(self):
        raise NotImplementedError

    def _set_attr_from_dbg(self, attrname):
        raise NotImplementedError

    def _temp_output_files(self):
        t = self.tempdir
        file_list = [os.path.join(t, f) for f in os.listdir(t)]
        return file_list

    def _verify_crash_base_dir(self):
        raise NotImplementedError

    def calculate_hamming_distances(self):
        try:
            self.hd_bits = hamming.bitwise_hamming_distance(self.seedfile.path, self.fuzzedfile.path)
            self.logger.info("bitwise_hd=%d", self.hd_bits)

            self.hd_bytes = hamming.bytewise_hamming_distance(self.seedfile.path, self.fuzzedfile.path)
            self.logger.info("bytewise_hd=%d", self.hd_bytes)
        except KeyError:
            # one of the files wasn't defined
            self.logger.warning('Cannot find either sf_path or minimized file to calculate Hamming Distances')

    def calculate_hamming_distances_a(self):
        with open(self.fuzzedfile.path, 'rb') as fd:
            fuzzed = fd.read()

        a_string = 'x' * len(fuzzed)

        self.hd_bits = hamming.bitwise_hd(a_string, fuzzed)
        self.logger.info("bitwise_hd=%d", self.hd_bits)

        self.hd_bytes = hamming.bytewise_hd(a_string, fuzzed)
        self.logger.info("bytewise_hd=%d", self.hd_bytes)

    def clean_tmpdir(self):
        logger.debug('Cleaning up %s', self.tempdir)
        if os.path.exists(self.tempdir):
            filetools.delete_files_or_dirs([self.tempdir])
        else:
            logger.debug('No tempdir at %s', self.tempdir)

        if os.path.exists(self.tempdir):
            logger.debug('Unable to remove tempdir %s', self.tempdir)

    def confirm_crash(self):
        raise NotImplementedError

    def copy_files(self, target=None):
        if not target:
            target = self.result_dir
        if not target or not os.path.isdir(target):
            raise CrashError("Target directory does not exist: %s" % target)

        logger.debug('Copying to %s', target)
        file_list = self._temp_output_files()
        for f in file_list:
            logger.debug('\t...file: %s', f)

        filetools.copy_files(target, *file_list)

    def copy_files_to_temp(self):
        if self.fuzzedfile and self.copy_fuzzedfile:
            filetools.copy_file(self.fuzzedfile.path, self.tempdir)

        if self.seedfile:
            filetools.copy_file(self.seedfile.path, self.tempdir)

        new_fuzzedfile = os.path.join(self.tempdir, self.fuzzedfile.basename)
        self.fuzzedfile = BasicFile(new_fuzzedfile)

    def debug(self, tries_remaining=None):
        raise NotImplementedError

    def debug_once(self):
        raise NotImplementedError

    def delete_files(self):
        if os.path.isdir(self.fuzzedfile.dirname):
            logger.debug('Deleting files from %s', self.fuzzedfile.dirname)
            filetools.delete_files_or_dirs([self.fuzzedfile.dirname])

    def get_debug_output(self, f):
        raise NotImplementedError

    def get_logger(self):
        raise NotImplementedError

    def get_result_dir(self):
        raise NotImplementedError

    def get_signature(self):
        raise NotImplementedError

    def set_debugger_template(self, option='bt_only'):
        raise NotImplementedError

    def update_crash_details(self):
        self.tempdir = tempfile.mkdtemp(prefix=self.tmpdir_pfx, dir=self.workdir_base)
        self.copy_files_to_temp()
#        raise NotImplementedError
