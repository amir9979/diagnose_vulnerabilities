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
Created on Oct 5, 2010

@organization: cert.org@cert.org

Provides the ability to calculate byte-wise or bit-wise Hamming Distance
between objects. P
'''
import itertools
import os

def vector_compare(v1, v2):
    '''
    Given two sparse vectors (lists of indices whose value is 1), return the distance between them
    '''
    vdict = {}

    for v in v1, v2:
        for idx in v:
            if vdict.get(idx):
                vdict[idx] += 1
            else:
                vdict[idx] = 1

    distance = 0
    for val in vdict.values():
        if val == 1:
            distance += 1

    return distance

def bytemap(s1, s2):
    '''
    Given two strings of equal length, return the indices of bytes that differ.
    '''
    assert len(s1) == len(s2)
    delta = []
    for idx, (c1, c2) in enumerate(itertools.izip(s1, s2)):
        if c1 != c2:
            delta.append(idx)
    return delta

def bytewise_hd(s1, s2):
    '''
    Compute the byte-wise Hamming Distance between two strings. Returns
    the distance as an int.
    '''
    assert len(s1) == len(s2)
    return sum(ch1 != ch2 for ch1, ch2 in itertools.izip(s1, s2))

def bytewise_hamming_distance(file1, file2):
    '''
    Given the names of two files, compute the byte-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bytewise_hd, file1, file2)

def _file_compare(distance_function, file1, file2):
    assert os.path.getsize(file1) == os.path.getsize(file2)

    f1 = open(file1, 'rb')
    f2 = open(file2, 'rb')

    distance = 0
    try:
        # find the hamming distance for each byte
        distance = distance_function(f1.read(), f2.read())
    finally:
        [fd.close() for fd in (f1, f2)]
    return distance

def bitwise_hd(x, y):
    '''
    Given two strings x and y, find the bitwise hamming distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless x and y are the same size.
    '''
    assert len(x) == len(y)

    hd = 0
    for (a, b) in itertools.izip(x, y):
        a = ord(a)
        b = ord(b)

        v = a ^ b
        while v:
            v = v & (v - 1)
            hd += 1
    return hd

def bitwise_hamming_distance(file1, file2):
    '''
    Given the names of two files, compute the bit-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bitwise_hd, file1, file2)
