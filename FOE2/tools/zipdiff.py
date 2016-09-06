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
Created on Jul 10, 2013

@organization: cert.org
'''

import os
import collections
import zipfile
from optparse import OptionParser

saved_arcinfo = collections.OrderedDict()

def readzip(filepath):
    global savedarcinfo
    # If the seed is zip-based, fuzz the contents rather than the container
    tempzip = zipfile.ZipFile(filepath, 'r')

    '''
    get info on all the archived files and concatentate their contents
    into self.input
    '''
    unzippedbytes = ''
    for i in tempzip.namelist():
        data = tempzip.read(i)

        # save split indices and compression type for archival reconstruction

        saved_arcinfo[i] = (len(unzippedbytes), len(data))
        unzippedbytes += data
    tempzip.close()
    return unzippedbytes

def main():
    global saved_arcinfo
    usage = 'usage: %prog zip1 zip2'
    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.error('Incorrect number of arguments')
        return

    changedbytes = []
    changedfiles = []

    zip1 = args[0]
    zip2 = args[1]
    zip1bytes = readzip(zip1)
    zip2bytes = readzip(zip2)
    zip1len = len(zip1bytes)

    if zip1len != len(zip2bytes):
        print 'Zip contents are not the same size. Aborting.'

    for i in range(0, zip1len):
        if zip1bytes[i] != zip2bytes[i]:
#            print 'Zip contents differ at offset %s' % i
            changedbytes.append(i)

    for changedbyte in changedbytes:
        for name, info in saved_arcinfo.iteritems():
            startaddr = info[0]
            endaddr = info[0] + info[1]
            if startaddr <= changedbyte <= endaddr and name not in changedfiles:
                print '%s modified' % name
                changedfiles.append(name)
            #print '%s: %s-%s' %(name, info[0], info[0]+info[1])

if __name__ == '__main__':
    main()
