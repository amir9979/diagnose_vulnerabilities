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

import random
import logging

from . import MinimizableFuzzer
from .fuzzer_base import _fuzzable

logger = logging.getLogger(__name__)

def fuzz(fuzz_input=None, seed_val=None, jump_idx=None, ratio_min=0.0,
         ratio_max=1.0, range_list=None, fuzzable_chars=None):
    '''
    Twiddle bytes of input and return output
    '''
    logging.debug('fuzz params: %d %d %f %f %s', seed_val, jump_idx, ratio_min, ratio_max, range_list)

    if seed_val is not None:
        random.seed(seed_val)
    if jump_idx is not None:
        random.jumpahead(jump_idx)

    ratio = random.uniform(ratio_min, ratio_max)
    inputlen = len(fuzz_input)

    chunksize = 2 ** 19  # 512k
    logger.debug('ratio=%f len=%d', ratio, inputlen)

    if range_list:
        chunksize = inputlen

    for chunk_start in xrange(0, inputlen, chunksize):
        chunk_end = min(chunk_start + chunksize, inputlen)
        chunk_len = chunk_end - chunk_start

        if range_list:
            chooselist = [x for x in xrange(inputlen) if _fuzzable(x, range_list)]
        else:
            chooselist = xrange(chunk_len)
        if fuzzable_chars is not None:
            chooselist = [x for x in chooselist if fuzz_input[x + chunk_start] in fuzzable_chars]

        nbytes_to_fuzz = int(round(ratio * len(chooselist)))
        bytes_to_fuzz = random.sample(chooselist, nbytes_to_fuzz)

        for idx in bytes_to_fuzz:
            offset = chunk_start + idx
            fuzz_input[offset] = random.getrandbits(8)

    return fuzz_input

class ByteMutFuzzer(MinimizableFuzzer):
    '''
    This fuzzer module randomly selects bytes in an input file and assigns
    them random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    Roughly similar to cmiller's 5 lines o' python, except clearly less space
    efficient.
    '''
    fuzzable_chars = None

    def _fuzz(self):
        self.range = self.sf.rangefinder.next_item()
        range_list = self.options.get('range_list')

        self.fuzzed = fuzz(fuzz_input=self.input,
                           seed_val=self.rng_seed,
                           jump_idx=self.iteration,
                           ratio_min=self.sf.ratio_min,
                           ratio_max=self.sf.ratio_max,
                           range_list=range_list,
                           fuzzable_chars=self.fuzzable_chars,
                           )

_fuzzer_class = ByteMutFuzzer
