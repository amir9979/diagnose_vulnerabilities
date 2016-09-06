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
Created on Apr 21, 2011

@organization: cert.org
'''
import os
import shutil
import tempfile
import logging
import platform
from ..fuzztools.filetools import delete_contents_of

logger = logging.getLogger(__name__)

class TmpReaper(object):
    '''
    classdocs
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.tmp_dir = tempfile.gettempdir()
        if platform.system() == 'Windows':
            self.clean_tmp = self.clean_tmp_windows
        else:
            self.clean_tmp = self.clean_tmp_unix

    def clean_tmp_windows(self, extras=[]):
        '''
        Removes as many of the contents of tmpdir as possible. Logs skipped
        files but otherwise won't block on the failure to delete something.
        '''
        paths_to_clear = set(extras)
        paths_to_clear.add(self.tmp_dir)
        skipped = delete_contents_of(paths_to_clear)
        for (skipped_item, reason) in skipped:
            logger.debug('Failed to delete %s: %s', skipped_item, reason)

    def clean_tmp_unix(self, extras=[]):
        '''
        Starts at the top level of tmpdir and deletes files or directories
        owned by the same uid as the current process.
        '''
        my_uid = os.getuid()

        for basename in os.listdir(self.tmp_dir):
            path = os.path.join(self.tmp_dir, basename)
            try:
                path_uid = os.stat(path).st_uid
                if my_uid == path_uid:
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
            except (IOError, OSError):
                # we don't mind these exceptions as they're usually indicative
                # of a file that got deleted before we could do the same
                continue
