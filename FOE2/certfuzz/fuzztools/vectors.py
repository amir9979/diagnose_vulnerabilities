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
Created on Feb 22, 2011

@organization: cert.org
'''
# from numpy import dot
# from numpy.linalg import norm
import math

def compare(d1, d2):
    '''
    Turn two dicts into vectors, then calculate their similarity
    @param d1: a dict with numeric values
    @param d2: a dict with numeric values
    '''

    # get the set of all keys for the two dicts
    k1 = set(d1.keys())
    k2 = set(d2.keys())
    keyset = k1.union(k2)

    # build vectors
    v1 = []
    v2 = []

    for k in keyset:
        v1.append(d1.get(k, 0))
        v2.append(d2.get(k, 0))

    return similarity(v1, v2)

def similarity(v1, v2):
    return cos(v1, v2)

def cos(v1, v2):
    assert len(v1) == len(v2), 'Cannot compare vectors of unequal length'
    dotproduct = float(dot(v1, v2))
    norm1 = float(norm(v1))
    norm2 = float(norm(v2))
    sim = dotproduct / (norm1 * norm2)
    sim = float('%.6f' % sim)  # fix for floating point very near 1.0 BFF-234
    assert 0 <= sim <= 1.0, 'Similarity out of range: %f' % sim

    return sim

def dot(v1, v2):
    '''
    Calculate the sum of the products of each term in v1 and v2
    @param v1:
    @param v2:
    '''
    assert len(v1) == len(v2), 'Vectors are different lengths'

    terms = zip(v1, v2)
    products = [float(x) * float(y) for (x, y) in terms]
    total = sum(products)
    return total

def norm(v):
    squares = [float(x) * float(x) for x in v]
    total = sum(squares)
    sqrt = math.sqrt(total)
    return sqrt

class Vector(object):
    def __init__(self, v):
        self.vector = v
