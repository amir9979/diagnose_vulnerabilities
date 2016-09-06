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
Created on May 8 2013

Provides the calltracefile class for analyzing pin calltrace output.

@organization: cert.org
'''
import re
import hashlib
import logging
from optparse import OptionParser
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

regex = {
        'ct_lib': re.compile(r'^/.+/(.+:.+)'),
        'ct_lib_function': re.compile(r'^(/.+):\s(.+)'),
        'ct_system_lib': re.compile(r'^/(usr/)?lib.+'),
         }

class Calltracefile:
    def __init__(self, f):
        '''
        Create a GDB file object from the gdb output file <file>
        @param lines: The lines of the gdb file
        @param is_crash: True if gdb file represents a crash
        @param is_assert_fail: True if gdb file represents an assert_fail
        @param is_debugbuild: True if gdb file contains source code lines
        '''
        logger.debug('initializing %s', f)
        self.file = f

        # collect data about the calltrace output
        self.backtrace = []
        self.hashable_backtrace = []
        self.hashable_backtrace_string = ''
        
        # Process lines one-by-one.  File can be huge
        with open(self.file) as pinfile:
            for line in pinfile:
                self.calltrace_line(line)
                
        self._hashable_backtrace()

    def _hashable_backtrace(self):
        logger.debug('_hashable_backtrace')
        hashable = []
        if not self.hashable_backtrace:
            for bt in self.backtrace:
                hashable.append(bt)

            if not hashable:
                self.is_crash = False
            self.hashable_backtrace = hashable
            logger.debug("hashable_backtrace: %s", self.hashable_backtrace)
        return self.hashable_backtrace

    def _hashable_backtrace_string(self, level):
        self.hashable_backtrace_string = ' '.join(self.hashable_backtrace[-level:]).strip()
        logger.warning('_hashable_backtrace_string: %s', self.hashable_backtrace_string)
        return self.hashable_backtrace_string

    def calltrace_line(self, l):
        m = re.match(regex['ct_lib'], l)
        if m:
            system_lib = re.match(regex['ct_system_lib'], l)
            n = re.match(regex['ct_lib_function'], l)
            if n:
                function = n.group(2)
            if not system_lib and function != '.plt' and function != '.text' and function != 'invalid_rtn':
                item = m.group(1)
                self.backtrace.append(item)
                logger.debug('Appending to backtrace: %s', item)

    def _process_lines(self):
        logger.debug('_process_lines')

        for idx, line in enumerate(self.lines):

            self.calltrace_line(idx, line)
            
    def get_crash_signature(self, backtrace_level):
        '''
        Determines if a crash is unique. Depending on <backtrace_level>,
        it may look at a number of source code lines in the gdb backtrace, or simply
        just the memory location of the crash.
        '''
        logger.debug('get_crash_signature')
        backtrace_string = self._hashable_backtrace_string(backtrace_level)
        if bool(backtrace_string):
            return hashlib.md5(backtrace_string).hexdigest()
        else:
            return False

if __name__ == '__main__':
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    for path in args:
        g = Calltracefile(path)
        print g.get_crash_signature(50)
