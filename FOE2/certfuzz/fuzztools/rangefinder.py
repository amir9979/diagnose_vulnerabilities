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
Created on Dec 8, 2010

@organization: cert.org
'''
import math
import logging

from ..scoring.scorable_set import ScorableSet2
from .range import Range

range_scale_factor = (math.sqrt(5) + 1.0) / 2.0

logger = logging.getLogger(__name__)
class RangeFinderError(Exception):
    pass

class RangeFinder(ScorableSet2):
    '''
    Provides facilities to maintain:
        1. a set of ranges (typically from min=1.0/filesize to max=1.0-1.0/filesize)
        2. scores for each range
        3. a probability distribution across all ranges
    as well as a picker method to randomly choose a range based on the probability distribution.
    '''
    def __init__(self, low, high, logfile, datafile=None):

        super(self.__class__, self).__init__(datafile=datafile)

        self.min = low
        self.max = high
        # the lowest range must have at least abs_min as its max
        # so that we don't wind up fuzzing a range of 0.000000:0.000000
        self.abs_min = 0.000001
        if self.max < self.min:
            raise RangeFinderError('max cannot be less than min')

        self.logfile = logfile
        logger.debug('Rangefinder log: %s', self.logfile)

        self._set_logger()

        self._set_ranges()

    def __getstate__(self):
        # we can't pickle the logger.
        # But that's okay. We can get it back in __setstate__
        state = ScorableSet2.__getstate__(self)
        del state['logger']
        return state

    def __setstate__(self, d):
        self.__dict__.update(d)
        for k, thing in self.things:
            assert type(thing) == Range, 'Type is %s' % type(thing)
        # recover the logger we had to drop in __getstate__
        self._set_logger()

    def _set_logger(self):
        self.logger = logging.getLogger(self.logfile)
        self.logger.setLevel(logging.INFO)

    def _exp_range(self, low, factor):
        high = low * factor
        # don't overshoot the high
        if high > self.max:
            high = self.max
        # don't undershoot abs_min
        if high < self.abs_min:
            high = self.abs_min
        return high

    def _set_ranges(self):
        rmin = self.min
        ranges = []
        while rmin < self.max:
            rmax = self._exp_range(rmin, range_scale_factor)
            ranges.append(Range(rmin, rmax))
            rmin = rmax

        # sometimes the last range might be smaller than the next to the last range
        # fix that if it happens
        (penultimate, ultimate) = ranges[-2:]
        if ultimate.span < penultimate.span:
            # create a new range to span both ranges
            merged_range = Range(penultimate.min, ultimate.max)
            # remove the last two ranges
            ranges = ranges[:-2]
            # and replace them with the merged range
            ranges.append(merged_range)

        for r in ranges:
            self.add_item(r.__repr__(), r)

        self.logger.debug('Ranges: [%s]', ', '.join([str(r) for r in self.things.keys()]))
