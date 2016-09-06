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
Created on Oct 22, 2010

Provides support for analyzing zzuf log files.

@organization: cert.org
'''
import re
import os
import filetools

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

class ZzufLog:
    def __init__(self, infile, outfile):
        '''
        Reads in <logfile> and parses *the last line*.
        @param logfile: the zzuf log file to analyze
        '''
        self.infile = infile
        self.outfile = outfile
        self.line = self._get_last_line()

        # parsed will get set True in _parse_line if we successfully parse the line
        self.parsed = False
        (self.seed, self.range, self.result) = self._parse_line()

        self.was_killed = self._was_killed()
        self.was_out_of_memory = self._was_out_of_memory()

        try:
            fp = open(self.outfile, 'a')
            fp.write("%s\n" % self.line)
        except Exception, e:
            logger.warning('Error writing to %s: %s', self.outfile, e)
        finally:
            fp.close()

        filetools.delete_files(self.infile)
        assert not os.path.exists(self.infile)

        self.exitcode = ''
        self._set_exitcode()

        self.signal = ''
        self._set_signal()

    def _set_signal(self):
        m = re.match('signal\s+(\d+)', self.result)
        if m:
            self.signal = m.group(1)

    def _set_exitcode(self):
        m = re.match('exit\s+(\d+)', self.result)
        if m:
            self.exitcode = int(m.group(1))

    def _get_last_line(self):
        '''
        Reads the zzuf log contained in <file> and returns the seed,
        range, result, and complete line from the last line of the file.
        @return: string, string, string, string
        '''
        f = open(self.infile, 'r')
        last_line = ""
        try:
            for l in f:
                last_line = l
        finally:
            f.close()

        return last_line.strip()

    def _parse_line(self):
        seed = False
        rng = False
        result = ''
        m = re.match('^zzuf\[s=(\d+),r=([^\]]+)\]:\s+(.+)$', self.line)
        if m:
            (seed, rng, result) = (int(m.group(1)), m.group(2), m.group(3))
            self.parsed = True  # set a flag that we parsed successfully
        return seed, rng, result

    def crash_logged(self, checkexit):
        '''
        Analyzes zzuf output log to figure out if this was a crash.
        Returns 0 if it's not really a crash. 1 if it's a crash we
        want. 2 if we're at a seed chunk boundary.
        '''
        # if we couldn't parse the log, just skip it and move on
        if not self.parsed:
            return False

        if checkexit and 'exit' in self.result:
            return False

        # not a crash if killed
        if self.was_killed:
            return False

        # not a crash if out of memory
        if self.was_out_of_memory:
            return False

        # if you got here, consider it a crash
        return True

    def _was_killed(self):
        for kill_indicator in ['signal 9', 'SIGXFSZ', 'Killed', 'exit 137']:
            if kill_indicator in self.result:
                return True
        return False

    def _was_out_of_memory(self):
        for out_of_memory_indicator in ['signal 15', 'exit 143']:
            if out_of_memory_indicator in self.result:
                return True
        return False
