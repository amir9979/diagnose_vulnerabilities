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
Created on Mar 18, 2011

@organization: cert.org
'''
import os
from ..fuzztools import filetools
from .basicfile import BasicFile
import logging
logger = logging.getLogger(__name__)

class DirectoryError(Exception):
    pass

blacklist = ['.DS_Store', ]

class Directory(object):
    def __init__(self, mydir, create=False):
        self.dir = mydir

        if create and not os.path.isdir(self.dir):
            if not os.path.exists(self.dir) and not os.path.islink(self.dir):
                filetools.make_directories(self.dir)
            else:
                raise DirectoryError('Cannot create dir %s - the path already exists, but is not a dir.' % self.dir)

        self._verify_dir()

        self.files = []
        self.refresh()

    def _verify_dir(self):
        if not os.path.exists(self.dir):
            raise DirectoryError('%s does not exist' % self.dir)
        if not os.path.isdir(self.dir):
            raise DirectoryError('%s is not a dir' % self.dir)

    def refresh(self):
        '''
        Gets all the file paths from self.dir then
        creates corresponding BasicFile objects in self.files
        '''
        self._verify_dir()

        dir_listing = [os.path.join(self.dir, f) for f in os.listdir(self.dir) if not f in blacklist]
        self.files = [BasicFile(path) for path in dir_listing if os.path.isfile(path)]

    def paths(self):
        '''
        Convenience function to get just the paths to the files
        instead of the file objects
        '''
        return [f.path for f in self.files]

    def __iter__(self):
        self.refresh()
        for f in self.files:
            yield f
