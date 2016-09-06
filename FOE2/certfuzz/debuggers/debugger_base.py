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
Created on Oct 23, 2012

@organization: cert.org
'''
import logging
from .registration import get_debug_file
from .registration import result_fields, allowed_exploitability_values
from .errors import DebuggerError

logger = logging.getLogger(__name__)

class Debugger(object):
    '''
    classdocs
    '''
    _platform = None
    _key = 'debugger'
    _ext = 'debug'

    def __init__(self, program=None, cmd_args=None, outfile_base=None, timeout=None, killprocname=None, **options):
        '''
        Default initializer for the base Debugger class.
        '''
        logger.debug('Initialize Debugger')
        self.program = program
        self.cmd_args = cmd_args
        self.outfile = get_debug_file(outfile_base, self._ext)
        self.timeout = timeout
        self.killprocname = killprocname
        self.input_file = ''
        self.debugger_output = None
        self.result = {}
        self._reset_result()
        self.seed = None
        self.faddr = None
        self.type = self._key
        self.debugger_output = ''
        self.debugheap = False
        logger.debug('DBG OPTS %s', options)

        # turn any other remaining options into attributes
        self.__dict__.update(options)
        logger.debug('DEBUGGER: %s', self.__dict__)

    def _reset_result(self):
        for key in result_fields:
            self.result[key] = None

    def _validate_exploitability(self):
        if not self.result['exp'] in allowed_exploitability_values:
            raise DebuggerError('Unknown exploitability value: %s' % self.result['exp'])

    def outfile_basename(self, basename):
        return '.'.join((basename, self.type))

    def write_output(self, target=None):
        if not target:
            target = self.outfile

        with open(target, 'w') as fd:
            fd.write(self.debugger_output)

    def carve(self, string, token1, token2):
        raise NotImplementedError

    def kill(self, pid, returncode):
        raise NotImplementedError

    def debug(self, input_filename):
        raise NotImplementedError

    def go(self):
        raise NotImplementedError

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        raise NotImplementedError

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        raise NotImplementedError
