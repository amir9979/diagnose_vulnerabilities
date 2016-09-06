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
Created on Oct 1, 2010

Contains various methods in support of zzuf.py.

@organization: cert.org
'''
import os
import sys
from ..fuzztools import subprocess_helper as subp
from ..fuzztools import filetools

def set_unbuffered_stdout():
    '''
    Reopens stdout with a buffersize of 0 (unbuffered)
    @rtype: none
    '''
    # reopen stdout file descriptor with write mode
    # and 0 as the buffer size (unbuffered)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

# analyze results
def get_crashcount(uniquedir):
    '''
    Counts the number of subdirs found in <uniquedir>.
    Returns the integer count of variants found.
    @rtype: int
    '''
    dirs = [d for d in os.listdir(uniquedir) if os.path.isdir(os.path.join(uniquedir, d))]
    return len(dirs)

def cache_program_once(cfg, seedfile):
    fullpathorig = cfg.full_path_original(seedfile)
    cmdargs = cfg.get_command_list(fullpathorig)
    subp.run_with_timer(cmdargs, cfg.progtimeout * 8, cfg.killprocname, use_shell=True)

def setup_dirs_and_files(cfg_file, cfg):
    # Set up a local fuzzing directory. HGFS or CIFS involves too much overhead, so
    # fuzz locally and then copy over interesting cases as they're encountered
    filetools.make_directories(*cfg.dirs_to_create)

    # Copy seed file and cfg to local fuzzing directory as well as fuzz run output directory
    # TODO: don't think we need this given Seedfile Dir Manager
#    filetools.copy_file(cfg.fullpathseedfile, cfg.fullpathlocalfuzzdir, cfg.output_dir)
    filetools.copy_file(cfg_file, cfg.output_dir)
