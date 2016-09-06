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
Created on Oct 24, 2012

@organization: cert.org
'''
import platform
import random
import string
from pprint import pformat, pprint
import logging

my_os = platform.system()

def quoted(string_to_wrap):
    return '"%s"' % string_to_wrap

def print_dict(d):
    pprint(d)

def check_os_compatibility(expected_os, module_name=__name__):
    if not my_os == expected_os:
        template = 'Module %s is incompatible with %s (%s expected)'
        raise ImportError(template % (module_name, my_os, expected_os))

def random_str(length=1):
    return ''.join(random.choice(string.letters) for dummy in xrange(length))

def bitswap(input_byte):
    bits = [1, 2, 4, 8, 16, 32, 64, 128]
    backwards = list(bits)
    backwards.reverse()
    # 1   -> 128
    # 2   -> 64
    # 4   -> 32
    # 8   -> 16
    # 16  -> 8
    # 32  -> 4
    # 64  -> 2
    # 128 -> 1
    output_byte = 0
    for x, y in zip(bits, backwards):
        # if bit x is set in input_byte,
        # set bit y in output_byte
        if input_byte & x:
            output_byte |= y
    return output_byte

def log_object(obj, logger, level=logging.DEBUG):
    for l in pformat(obj.__dict__).splitlines():
        logger.log(level, '%s', l)
