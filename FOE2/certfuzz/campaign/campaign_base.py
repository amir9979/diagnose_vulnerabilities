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

The certfuzz.campaign package provides modules to manage fuzzing campaigns,
configurations, and iterations.

@organization: cert.org
'''
import abc
import sys
import os

from . import __version__
from ..fuzztools import filetools

def import_module_by_name(name, logger=None):
    if logger:
        logger.debug('Importing module %s', name)
    __import__(name)
    module = sys.modules[name]
    return module

class CampaignError(Exception):
    pass

class CampaignBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, config_file, result_dir=None, campaign_cache=None, debug=False):
        self.config_file = config_file
        self.cached_state_file = campaign_cache
        self.debug = debug
        self._version = __version__

    @abc.abstractmethod
    def __enter__(self):
        return self

    @abc.abstractmethod
    def __exit__(self, etype, value, mytraceback):
        pass

    @abc.abstractmethod
    def __getstate__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def __setstate__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _do_interval(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _do_iteration(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _keep_going(self):
        '''
        Returns True if a campaign should proceed. False otherwise.
        '''
        return True

    @abc.abstractmethod
    def _write_version(self):
        version_file = os.path.join(self.outdir, 'version.txt')
        version_string = 'Results produced by %s v%s' % (__name__, __version__)
        filetools.write_file(version_string, version_file)

    @abc.abstractmethod
    def go(self):
        '''
        Executes a fuzzing campaign. Will continue until either we run out of
        iterations or the user issues a KeyboardInterrupt (ctrl-C).
        '''
        while self._keep_going():
            self._do_interval()
