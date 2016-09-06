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
Created on Mar 14, 2012

@author: adh
'''
import logging

from . import DebuggerFile

logger = logging.getLogger(__name__)

required_checks = ['crash_hash', 'exploitability']

class MsecFile(DebuggerFile):
    '''
    classdocs
    '''
    _key = 'msec'

    def __init__(self, *args, **kwargs):
        self.crash_hash = None
        self.exp = None
        self.faddr = None
        self.secondchance = False

        # add our callbacks
        self.line_callbacks = [
                               self._find_exploitability,
                               self._find_efa,
                               self._find_hash,
                               self._find_secondchance,
                               ]

        self.passed = set()
        # initialize our parent class
        DebuggerFile.__init__(self, *args, **kwargs)

        # override the default from DebuggerFile
        self.is_crash = False

        required_checks = ['crash_hash', 'exploitability']
        checks_passed = [x in self.passed for x in required_checks]
        self.is_crash = all(checks_passed)

#        if self.lines:
#            self.debugger_output = '\n'.join(self.lines)

    def _process_backtrace(self):
        pass

    def _hashable_backtrace(self):
        pass

    def get_crash_signature(self, backtrace_level):
        return self.crash_hash

    def _find_exploitability(self, line):
        if line.startswith('Exploitability Classification'):
            exploitability = self.split_and_strip(line)

            # Count it as a crash as long as it has a classification
            if exploitability and exploitability != 'NOT_AN_EXCEPTION':
                self.passed.add('exploitability')

            self.exp = exploitability
            self.line_callbacks.remove(self._find_exploitability)

    def _find_efa(self, line):
        if line.startswith('Exception Faulting Address'):
            efa = self.split_and_strip(line)
            # turn it into a properly formatted string
            self.faddr = '0x%08x' % int(efa, 16)
            self.line_callbacks.remove(self._find_efa)

    def _find_hash(self, line):
        if line.startswith('Exception Hash'):
            crash_hash = self.split_and_strip(line)
            # count it as a crash as long as it has a hash
            if crash_hash:
                self.passed.add('crash_hash')

            self.crash_hash = crash_hash
            self.line_callbacks.remove(self._find_hash)

    def _find_secondchance(self, line):
        if '!!! second chance !!!' in line:
            self.secondchance = True
            self.line_callbacks.remove(self._find_secondchance)

    def split_and_strip(self, line, delim=':'):
        '''
        Return the second half of the line after the delimiter, stripped of
        whitespace
        @param line:
        @param delim: defaults to ":"
        '''
        return line.split(delim)[1].strip()
