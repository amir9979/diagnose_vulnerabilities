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

import logging
from . import Minimizer as MinimizerBase
from ..fuzztools.filetools import write_file
from ..fuzztools.filetools import check_zip_file
import zipfile
import collections
from .errors import WindowsMinimizerError

logger = logging.getLogger(__name__)

class WindowsMinimizer(MinimizerBase):
    use_watchdog = False

    def __init__(self, cfg=None, crash=None, crash_dst_dir=None,
                 seedfile_as_target=False, bitwise=False, confidence=0.999,
                 logfile=None, tempdir=None, maxtime=3600, preferx=False, keep_uniq_faddr=False, watchcpu=False):

        self.saved_arcinfo = None
        self.is_zipfile = check_zip_file(crash.fuzzedfile.path)

        MinimizerBase.__init__(self, cfg, crash, crash_dst_dir, seedfile_as_target,
                               bitwise, confidence, logfile, tempdir, maxtime,
                               preferx, keep_uniq_faddr, watchcpu)

    def get_signature(self, dbg, backtracelevels):
        # get the basic signature
        crash_hash = MinimizerBase.get_signature(self, dbg, backtracelevels)
        if not crash_hash:
            self.signature = None
        else:
            crash_id_parts = [crash_hash]
            if self.crash.keep_uniq_faddr and hasattr(dbg, 'faddr'):
                crash_id_parts.append(dbg.faddr)
            self.signature = '.'.join(crash_id_parts)
        return self.signature

    def _read_fuzzed(self):
        '''
        returns the contents of the fuzzed file
        '''
        # store the files in memory
        if self.is_zipfile:  # work with zip file contents, not the container
            logger.debug('Working with a zip file')
            return self._readzip(self.crash.fuzzedfile.path)
        # otherwise just call the parent class method
        return MinimizerBase._read_fuzzed(self)

    def _read_seed(self):
        '''
        returns the contents of the seed file
        '''
        # we're either going to minimize to the seedfile, the metasploit
        # pattern, or a string of 'x's
        if self.is_zipfile and self.seedfile_as_target:
            return self._readzip(self.crash.seedfile.path)
        # otherwise just call the parent class method
        return MinimizerBase._read_seed(self)

    def _readzip(self, filepath):
        # If the seed is zip-based, fuzz the contents rather than the container
        logger.debug('Reading zip file: %s', filepath)
        tempzip = zipfile.ZipFile(filepath, 'r')

        '''
        get info on all the archived files and concatentate their contents
        into self.input
        '''
        self.saved_arcinfo = collections.OrderedDict()
        unzippedbytes = ''
        logger.debug('Reading files from zip...')
        for i in tempzip.namelist():
            data = tempzip.read(i)

            # save split indices and compression type for archival
            # reconstruction. Keeping the same compression types is
            # probably unnecessary since it's the content that matters

            self.saved_arcinfo[i] = (len(unzippedbytes), len(data),
                                        tempzip.getinfo(i).compress_type)
            unzippedbytes += data
        tempzip.close()
        return unzippedbytes

    def _writezip(self):
        '''rebuild the zip file and put it in self.fuzzed
        Note: We assume that the fuzzer has not changes the lengths
        of the archived files, otherwise we won't be able to properly
        split self.fuzzed
        '''
        if self.saved_arcinfo is None:
            raise WindowsMinimizerError('_readzip was not called')

        filedata = ''.join(self.newfuzzed)
        filepath = self.tempfile

        logger.debug('Creating zip with mutated contents.')
        tempzip = zipfile.ZipFile(filepath, 'w')

        '''
        reconstruct archived files, using the same compression scheme as
        the source
        '''
        for name, info in self.saved_arcinfo.iteritems():
            # write out fuzzed file
            if info[2] == 0 or info[2] == 8:
                # Python zipfile only supports compression types 0 and 8
                compressiontype = info[2]
            else:
                logger.warning('Compression type %s is not supported. Overriding', info[2])
                compressiontype = 8
            tempzip.writestr(name, str(filedata[info[0]:info[0] + info[1]]), compress_type=compressiontype)
        tempzip.close()

    def _write_file(self):
        if self.is_zipfile:
            self._writezip()
        else:
            write_file(''.join(self.newfuzzed), self.tempfile)
