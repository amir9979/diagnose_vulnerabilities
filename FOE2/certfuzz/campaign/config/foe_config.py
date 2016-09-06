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
Created on Feb 9, 2012

@organization: cert.org
'''
import logging
from string import Template

from . import Config as ConfigBase
from . import ConfigError
from ...helpers import quoted
import shlex

logger = logging.getLogger(__name__)

def get_command_args_list(cmd_template, infile, posix=True):
    '''
    Given a command template and infile, will substitute infile into the
    template, and return both the complete string and its component parts
    as returned by shlex.split. The optional posix parameter is passed to
    shlex.split (defaults to true).
    :param cmd_template: a string.Template object containing "$SEEDFILE"
    :param infile: the string to substitute for "$SEEDFILE" in cmd_template
    :param posix: (optional) passed through to shlex.split
    '''
    cmd = cmd_template.substitute(SEEDFILE=infile)
    cmdlist = shlex.split(cmd, posix=posix)
    return cmd, cmdlist

class Config(ConfigBase):
    def _add_validations(self):
        self.validations.append(self._validate_debugger_timeout_exceeds_runner)
        self.validations.append(self._validate_new_options)

    def _set_derived_options(self):
        # interpolate program name
        # add quotes around $SEEDFILE
        t = Template(self.config['target']['cmdline_template'])
#        self.config['target']['cmdline_template'] = t.safe_substitute(PROGRAM=self.config['target']['program'])
        self.config['target']['cmdline_template'] = t.safe_substitute(PROGRAM=quoted(self.config['target']['program']),
                          SEEDFILE=quoted('$SEEDFILE'))
        
    def _validate_new_options(self):
        if 'minimizer_timeout' not in self.config['runoptions']:
            self.config['runoptions']['minimizer_timeout'] = 3600

    def _validate_debugger_timeout_exceeds_runner(self):
        try:
            runner_section = self.config['runner']
        except KeyError:
            return

        # if runner is null, we're just going to use the debugger timeout
        try:
            runner = runner_section['runner']
            if not runner:
                return

        except KeyError:
            return

        try:
            run_timeout = runner_section['runtimeout']
        except KeyError:
            return

        if not run_timeout:
            raise ConfigError('Runner timeout cannot be zero')

        try:
            debugger_section = self.config['debugger']
        except KeyError:
            return

        try:
            dbg_timeout = debugger_section['runtimeout']
        except KeyError:
            return

        if not dbg_timeout:
            raise ConfigError('Debugger timeout cannot be zero')

        if dbg_timeout < (2 * run_timeout):
            logger.warning('Debugger timeout must be >= 2 * runner timeout.')
            self.config['debugger']['runtimeout'] = 2.0 * run_timeout
            logger.warning('Setting debugger timeout = %s instead', self.config['debugger']['runtimeout'])
