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
Created on Apr 12, 2011

@organization: cert.org
'''
import logging
import os

from .directory import Directory
from ..fuzztools import filetools
from .seedfile import SeedFile, SeedFileError
from ..scoring.scorable_set import ScorableSet2, EmptySetError
logger = logging.getLogger(__name__)

class SeedfileSet(ScorableSet2):
    '''
    classdocs
    '''
    def __init__(self, campaign_id=None, originpath=None, localpath=None,
                 outputpath='.', logfile=None, datafile=None):
        '''
        Constructor
        '''

        if not datafile:
            datafile = os.path.join(outputpath, 'seedfile_set_data.csv')

        super(self.__class__, self).__init__(datafile=datafile)

        self.campaign_id = campaign_id
        self.seedfile_output_base_dir = outputpath

        self.originpath = originpath
        self.localpath = localpath
        # TODO: merge self.outputpath with self.seedfile_output_base_dir
        self.outputpath = outputpath

        self.origindir = None
        self.localdir = None
        self.outputdir = None

        if logfile:
            hdlr = logging.FileHandler(logfile)
            logger.addHandler(hdlr)

        logger.debug('SeedfileSet output_dir: %s', self.seedfile_output_base_dir)

    def __enter__(self):
        self._setup()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _setup(self):
        self._set_directories()
        self._copy_files_to_localdir()
        self._add_local_files_to_set()

    def _set_directories(self):
        if self.originpath:
            self.origindir = Directory(self.originpath)
        if self.localpath:
            self.localdir = Directory(self.localpath, create=True)
        if self.outputpath:
            self.outputdir = Directory(self.outputpath, create=True)

    def _copy_files_to_localdir(self):
        for f in self.origindir:
            self.copy_file_from_origin(f)

    def _add_local_files_to_set(self):
        self.localdir.refresh()
        files_to_add = [f.path for f in self.localdir]
        self.add_file(*files_to_add)

    def add_file(self, *files):
        for f in files:
            try:
                seedfile = SeedFile(self.seedfile_output_base_dir, f)
            except SeedFileError:
                logger.warning('Skipping empty file %s', f)
                continue
            logger.info('Adding file to set: %s', seedfile.path)
            self.add_item(seedfile.md5, seedfile)

    def copy_file_from_origin(self, f):
        if (os.path.basename(f.path) == '.DS_Store'):
            return 0

        # convert the local filenames from <foo>.<ext> to <md5>.<ext>
        basename = 'sf_' + f.md5 + f.ext
        targets = [os.path.join(d, basename) for d in (self.localpath, self.outputpath)]
        filetools.copy_file(f.path, *targets)
        for target in targets:
            filetools.make_writable(target)
        return 1

    def paths(self):
        for x in self.things.values():
            yield x.path

    def next_item(self):
        '''
        Returns a seedfile object selected per the scorable_set object.
        Verifies that the seedfile exists, and removes any nonexistent
        seedfiles from the set
        '''
        if not len(self.things):
            raise EmptySetError

        while len(self.things):
            logger.debug('Thing count: %d', len(self.things))
            # continue until we find one that exists, or else the set is empty
            sf = ScorableSet2.next_item(self)
            if sf.exists():
                # it's still there, proceed
                return sf
            else:
                # it doesn't exist, remove it from the set
                logger.warning('Seedfile no longer exists, removing from set: %s', sf.path)
                self.del_item(sf.md5)

    def __setstate__(self, state):
        newstate = state.copy()

        # copy out old things and replace with an empty dict
        oldthings = newstate.pop('things')
        newstate['things'] = {}

        # refresh the directories
        self.__dict__.update(newstate)
        self._setup()

        # clean up things that no longer exist
        self.sfcount = 0
        self.sfdel = 0
        for k, old_sf in oldthings.iteritems():
            # update the seedfiles for ones that are still present
            if k in self.things:
#                print "%s in things..." % k
                self.things[k].__setstate__(old_sf)
                self.sfcount += 1

    def __getstate__(self):
        state = ScorableSet2.__getstate__(self)

        # remove things we can recreate
        try:
            for k in ('origindir', 'localdir', 'outputdir'):
                del state[k]
        except KeyError:
            # it's ok if they don't exist
            pass

        return state
