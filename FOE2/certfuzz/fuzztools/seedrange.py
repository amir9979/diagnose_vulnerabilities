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
Created on Jan 7, 2011

@organization: cert.org
'''
START_SEED = 0
SEED_INTERVAL = 500
MAX_SEED = 1e10

class SeedRange():
    def __init__(self, start_seed=START_SEED, interval=SEED_INTERVAL, max_seed=MAX_SEED):
        self.initial_seed = start_seed
        self.s1 = start_seed
        self.interval = interval
        self.max_seed = max_seed

        self.verify_parameters()

        self.set_s2()

    def verify_parameters(self):
        assert isinstance(self.initial_seed, int), 'initial seed must be an int'
        assert isinstance(self.s1, int), 's1 must be an int'
        assert isinstance(self.interval, int), 'seed interval must be an int'
        assert self.s1 < self.max_seed

    def set_s1_to_s2(self):
        self.s1 = self.s2

    def set_s2(self):
        self.s2 = self.s1 + self.interval

    def increment_seed(self):
        self.s1 += 1

    def in_range(self):
        return self.s1 < self.s2

    def in_max_range(self):
        return self.s1 < self.max_seed

    def bookmark_s1(self):
        self._s1_bookmark = self.s1

    def s1_delta(self):
        return self.s1 - self._s1_bookmark + 1

    def s1_s2_delta(self):
        return self.s2 - self.s1
