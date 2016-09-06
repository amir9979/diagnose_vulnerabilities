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
import os
import subprocess
import platform
from .errors import UndefinedDebuggerError, DebuggerNotFoundError

logger = logging.getLogger(__name__)

result_fields = 'debug_crash crash_hash exp faddr output dbg_type'.split()
allowed_exploitability_values = ['UNKNOWN', 'PROBABLY_NOT_EXPLOITABLE',
                                 'PROBABLY_EXPLOITABLE', 'EXPLOITABLE']

# remember the system platform (we'll use it a lot)
system = platform.system()

# the keys for debugger_for should match strings returned by platform.system()
debugger_for = {
                # platform: key
#                'Linux': 'gdb',
#                'Darwin': 'crashwrangler',
#                'Windows': 'msec',
                }

debugger_class_for = {
                      # key: class
#                      'gdb': GDB,
#                      'crashwrangler': CrashWrangler,
#                      'msec': MsecDebugger,
                      }

debugger_ext = {
                # key: ext
#                'gdb': 'gdb',
#                'crashwrangler': 'cw',
#                'msec': 'msec',
                }

debugger = None
debug_class = None.__class__
debug_ext = None

def register(cls=None):
#    logger.debug('Registering debugger for %s: key=%s class=%s ext=%s',
#                 cls._platform, cls._key, cls.__name__, cls._ext)
    debugger_for[cls._platform] = cls._key
    debugger_class_for[cls._key] = cls
    debugger_ext[cls._key] = cls._ext

def verify_supported_platform():
    global debugger
    global debug_class
    global debug_ext
    # make sure that we're running on a supported platform
    try:
        debugger = debugger_for[system]
        debug_class = debugger_class_for[debugger]
        debug_ext = debugger_ext[debugger]
    except KeyError:
        raise UndefinedDebuggerError(system)

    if not system in debugger_for.keys():
        raise UndefinedDebuggerError(system)

    try:
        dbg = debug_class(None, None, None, None, None)
        with open(os.devnull, 'w') as devnull:
            subprocess.call(dbg.debugger_test(), stderr=devnull,
                            stdout=devnull)
    except OSError:
        raise DebuggerNotFoundError(debugger)
    except TypeError:
        logger.warning('Skipping debugger test for debugger %s', debugger)

def get_debug_file(basename, ext=debug_ext):
    return "%s.%s" % (basename, ext)

def get():
    '''
    Returns a debugger class to be instantiated
    @param system: a string specifying which system you're on
    (output of platform.system())
    '''
    return debug_class
