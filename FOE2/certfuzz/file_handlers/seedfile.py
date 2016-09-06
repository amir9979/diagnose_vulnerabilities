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
Created on Mar 16, 2011

@organization: cert.org
'''
import os
import json

from .basicfile import BasicFile, BasicFileError
from ..fuzztools.rangefinder import RangeFinder
from ..fuzztools import filetools
from ..scoring.scorable_thing import ScorableThing

# TODO: replace with a common function in some helper module
def print_dict(d, indent=0):
    for (k, v) in d.iteritems():
        indent_str = '  ' * indent
        if isinstance(v, dict):
            print indent_str + k
            print_dict(v, indent + 1)
        else:
            print indent_str + "%s (%s): %s" % (k, type(v).__name__, v)

class SeedFileError(BasicFileError):
    pass

# ScorableThing mixin gives us the probability stuff needed for use as part of
# a scorable set like SeedfileSet
class SeedFile(BasicFile, ScorableThing):
    '''
    '''

    def __init__(self, output_base_dir, *args):
        '''
        Creates an output dir for this seedfile based on its md5 hash.
        @param output_base_dir: The base directory for output files
        @raise SeedFileError: zero-length files will raise a SeedFileError
        '''
        BasicFile.__init__(self, *args)
        ScorableThing.__init__(self, key=self.md5)

        if not self.len > 0:
            raise SeedFileError('You cannot do bitwise fuzzing on a zero-length file: %s' % self.path)

        self.output_dir = os.path.join(output_base_dir, self.md5)
        # use len for bytewise, bitlen for bitwise
        if self.len > 1:
            self.range_min = 1.0 / self.len
            self.range_max = 1.0 - self.range_min
        else:
            self.range_min = 0
            self.range_max = 1

        # output_dir might not exist, so create it
        if not os.path.exists(self.output_dir):
            filetools.make_directories(self.output_dir)

        self.rangefinder = self._get_rangefinder()

    def _get_rangefinder(self):
        rf_log = os.path.join(self.output_dir, 'rangefinder.log')
        return RangeFinder(self.range_min, self.range_max, rf_log)

    def __getstate__(self):
        '''
        Pickle a SeedFile object
        @return a dict representation of the pickled object
        '''
        state = self.__dict__.copy()
        state['rangefinder'] = self.rangefinder.__getstate__()
        return state

    def __setstate__(self, state):
        old_rf = state.pop('rangefinder')

        self.a = state['a']
        self.b = state['b']
        self.seen = state['seen']
        self.successes = state['successes']
        self.tries = state['tries']
        self.uniques_only = state['uniques_only']

        # rebuild the rangefinder
        new_rf = self._get_rangefinder()
        old_ranges = old_rf['things']
        for k, old_range in old_ranges.iteritems():
            if k in new_rf.things:
                # things = ranges
                new_range = new_rf.things[k]
                for attr in ['a', 'b', 'probability', 'seen', 'successes', 'tries']:
                    setattr(new_range, attr, old_range[attr])
        self.rangefinder = new_rf

    def cache_key(self):
        return 'seedfile-%s' % self.md5

    def pkl_file(self):
        return '%s.pkl' % self.md5

    def to_json(self, sort_keys=True, indent=None):
        state = self.__dict__.copy()
        state['rangefinder'] = state['rangefinder'].to_json(sort_keys=sort_keys, indent=indent)
        return json.dumps(state, sort_keys=sort_keys, indent=indent)
