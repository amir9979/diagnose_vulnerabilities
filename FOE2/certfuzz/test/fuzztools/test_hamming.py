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

from certfuzz.fuzztools.hamming import bitwise_hd
from certfuzz.fuzztools.hamming import bytewise_hamming_distance
from certfuzz.fuzztools.hamming import bytemap
from certfuzz.fuzztools.hamming import bitwise_hamming_distance
from certfuzz.fuzztools.hamming import vector_compare
from certfuzz.fuzztools.hamming import bytewise_hd
import os
import tempfile
import itertools

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Test(unittest.TestCase):

    def delete_files(self, *files):
        for f in files:
            os.remove(f)
            self.assertFalse(os.path.exists(f))

    def setUp(self):
        (f1d, f1) = tempfile.mkstemp(text=True)
        (f2d, f2) = tempfile.mkstemp(text=True)
        [os.close(fd) for fd in (f1d, f2d)]
        self.f1 = f1
        self.f2 = f2

    def tearDown(self):
        self.delete_files(self.f1, self.f2)

    def test_bytewise_hd(self):
        s1 = "xxxxxxxxxxxxxx"
        s2 = "12xx345xxxx678"
        s3 = "000x00000xx00x"

        self.assertEqual(bytewise_hd(s1, s2), 8)
        self.assertEqual(bytewise_hd(s2, s3), 11)
        self.assertEqual(bytewise_hd(s1, s3), 10)
        self.assertEqual(bytewise_hd(s1, s1), 0)
        self.assertEqual(bytewise_hd(s2, s2), 0)
        self.assertEqual(bytewise_hd(s3, s3), 0)

        # reject strings of different length
        self.assertRaises(AssertionError, bytewise_hd, s1, s2 + "foo")

    def test_bitwise_hd(self):
        # '0' = 0110000
        # '1' = 0110001
        # 'a' = 1100001
        # 'c' = 1100011
        self.assertEqual(bitwise_hd('0', '1'), 1)
        self.assertEqual(bitwise_hd('0', 'a'), 3)
        self.assertEqual(bitwise_hd('0', 'c'), 4)
        self.assertEqual(bitwise_hd('1', 'a'), 2)
        self.assertEqual(bitwise_hd('1', 'c'), 3)
        self.assertEqual(bitwise_hd('a', 'c'), 1)
        [self.assertEqual(bitwise_hd(c, c), 0) for c in "01ac"]

    def test_bytwise_hamming_distance(self):
        # set up some temp files
        f1d = open(self.f1, 'w')
        f2d = open(self.f2, 'w')
        f1d.write("xxxxxxxxxxxxxx")
        f2d.write("12xx345xxxx678")
        f1d.close()
        f2d.close()

        self.assertEqual(bytewise_hamming_distance(self.f1, self.f2), 8)
        self.assertEqual(bytewise_hamming_distance(self.f1, self.f1), 0)
        self.assertEqual(bytewise_hamming_distance(self.f2, self.f2), 0)

    def test_bytemap(self):
        # character positions
        #     00000000001111
        #     01234567890123
        s1 = "xxxxxxxxxxxxxx"
        s2 = "12xx345xxxx678"
        s3 = "000x00000xx00x"

        self.assertEqual(bytemap(s1, s2), [0, 1, 4, 5, 6, 11, 12, 13])
        self.assertEqual(bytemap(s1, s3), [0, 1, 2, 4, 5, 6, 7, 8, 11, 12])
        self.assertEqual(bytemap(s2, s3), [0, 1, 2, 4, 5, 6, 7, 8, 11, 12, 13])
        self.assertEqual(bytemap(s1, s1), [])
        self.assertEqual(bytemap(s2, s2), [])
        self.assertEqual(bytemap(s3, s3), [])

        # does it work with bytearrays?
        for x, y in itertools.product([s1, s2, s3], [s1, s2, s3]):
            self.assertEqual(bytemap(bytearray(x), bytearray(y)), bytemap(x, y))

        # reject strings of different length
        self.assertRaises(AssertionError, bytemap, s1, s2 + "foo")

    def test_bitwise_hamming_distance(self):
        # set up some temp files
        # set up some temp files
        f1d = open(self.f1, 'w')
        f2d = open(self.f2, 'w')
        f1d.write("aaaaaaaaa")
        f2d.write("acaacaxac")
        f1d.close()
        f2d.close()

        self.assertEqual(bitwise_hamming_distance(self.f1, self.f2), 6)
        self.assertEqual(bitwise_hamming_distance(self.f1, self.f1), 0)
        self.assertEqual(bitwise_hamming_distance(self.f2, self.f2), 0)

    def test_vector_compare(self):
        v1 = [0, 1, 2, 3]
        v2 = [2, 3, 4, 5]
        v3 = [2]
        self.assertEqual(vector_compare(v1, v2), 4)
        self.assertEqual(vector_compare(v1, v3), 3)
        self.assertEqual(vector_compare(v2, v3), 3)
        self.assertEqual(vector_compare(v1, v1), 0)
        self.assertEqual(vector_compare(v2, v2), 0)
        self.assertEqual(vector_compare(v3, v3), 0)

if __name__ == "__main__":
    unittest.main()
