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

from . import MinimizableFuzzer
from random import jumpahead, sample, uniform, seed
import logging

logger = logging.getLogger(__name__)

class BitMutFuzzer(MinimizableFuzzer):
    '''
    This fuzzer module randomly selects bits in an input file and flips them.
    The percent of the selected bits can be tweaked by min_ratio and max_ratio.
    range_list specifies a range in the file to fuzz. Roughly similar to zzuf's
    mutation strategy.
    '''
    def _fuzz(self):
        """Twiddle bits of input_file_path and write output to output_file_path"""
        # rng_seed is the based on the input file
        seed(self.rng_seed)
        jumpahead(self.iteration)

        # select a ratio of bytes to fuzz
        self.range = self.sf.rangefinder.next_item()
        self.ratio = uniform(self.range.min, self.range.max)

        chooselist = []
        # only add bytes in range to the bytes we can fuzz
        range_list = self.options.get('range_list')
        if range_list:
            max_index = len(self.input) - 1
            for (start, end) in range_list:
                if start > end:
                    logger.warning('Skipping range_list item %s-%s (start exceeds end)', start, end)
                    continue
                elif start > max_index:
                    # we can't go past the end of the file
                    logger.debug('Skipping range_list item %s-%s (start exceeds max)', start, end)
                    continue

                # figure out where the actual end of this range is
                last = min(end, max_index)
                if last != end:
                    logger.debug('Reset range end from to %s to %s (file length exceeded)', end, last)

                # seems legit...proceed
                chooselist.extend(xrange(start, last + 1))
        else:
            # they're all available to fuzz
            chooselist.extend(xrange(len(self.input)))

        # build the list of bits we're allowed to flip
        # since chooselist is the list of bytes we can fuzz
        # protobitlist will be the base position of the first
        # bit we are allowed to fuzz in each of those bytes
        protobitlist = [x * 8 for x in chooselist]
        bitlist = []
        for b in protobitlist:
            for i in xrange(0, 8):
                # here we fill in the actual bits we are
                # allowed to fuzz
                # this will add b, b+1, b+2...b+7
                bitlist.append(b + i)

        # calculate num of bits to flip
        bit_flip_count = int(round(self.ratio * len(bitlist)))
        indices_to_flip = sample(bitlist, bit_flip_count)

        # create mask to xor with input
        mask = bytearray(len(self.input))
        for i in indices_to_flip:
            (byte_index, bit_index) = divmod(i, 8)
            mask[byte_index] = mask[byte_index] | (1 << bit_index)

        # apply the mask to the input
        for idx, val in enumerate(self.input):
            self.input[idx] = mask[idx] ^ val

        self.fuzzed = self.input

_fuzzer_class = BitMutFuzzer
