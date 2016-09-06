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

"""
"""
from . import Fuzzer
from . import FuzzerError
from . import FuzzerExhaustedError
import logging
from random import getrandbits

logger = logging.getLogger(__name__)

class InsertFuzzerError(FuzzerError):
    pass

class InsertFuzzer(Fuzzer):
    '''
    This fuzzer module iterates through an input file, inserting a random byte
    between every byte position as it goes. E.g. insert before byte 0, before
    byte 1, etc.
    '''
    def _fuzz(self):
        '''
        Insert individual bytes of input and put output in self.fuzzed
        '''

        # TODO: add range list support to insert fuzzer
#        if self.options.get('use_range_list'):
#            bytes_to_fuzz = []
#            for (start, end) in self.options['range_list']:
#                    bytes_to_fuzz.extend(xrange(start, end + 1))
#        else:
#            bytes_to_fuzz = xrange(len(byte_buffer))
        bytes_to_fuzz = xrange(len(self.input))

        # we can calculate the byte to insert on based on the number of tries
        # on this seed file
        byte_pos = self.sf.tries
        byte_to_insert = getrandbits(8)

        if byte_pos < len(bytes_to_fuzz):
            self.input.insert(byte_pos, byte_to_insert)
        else:
            #indicate we didn't fuzz the file for this iteration
            raise FuzzerExhaustedError('Iteration exceeds available values')

        logger.debug('%s - inserted byte 0x%02x at 0x%02x', self.sf.basename,
                     byte_to_insert, byte_pos)

        self.fuzzed = self.input

_fuzzer_class = InsertFuzzer
