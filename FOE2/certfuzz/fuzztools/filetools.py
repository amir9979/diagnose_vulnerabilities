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
Created on Oct 21, 2010

Provides basic file system tools for creating directories, copying files, writing to files, and deleting files.

@organization: cert.org
'''
import os
import errno
import time
import shutil
import hashlib
import logging
import tempfile
import fnmatch
import stat
import zipfile
import StringIO

MAXDEPTH = 5
SLEEPTIMER = 0.5
BACKOFF_FACTOR = 2

logger = logging.getLogger(__name__)

def exponential_backoff(F):
    def wrapper(*args, **kwargs):
        naptime = 0.0
        for current_depth in range(MAXDEPTH):
            if naptime:
                logger.debug('... pause for %0.1fs', naptime)
                time.sleep(naptime)
            try:
                return F(*args, **kwargs)
            except Exception as detail:
                logmsg = '... [try %d of %d]: %s' % (current_depth + 1, MAXDEPTH, detail)
                logger.debug(logmsg)
            # increment naptimefor the next time around
            naptime = SLEEPTIMER * pow(BACKOFF_FACTOR, current_depth)
        raise

    return wrapper

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        # if the dir already exists, just move along
        if exc.errno == errno.EEXIST:
            pass
        else: raise

# file system helpers
def make_directories(*paths):
    '''
    Creates directories given a list of <paths>
    @return: none
    '''
    for d in paths:
        if not os.path.exists(d):
            mkdir_p(d)

def find_or_create_dir(dir):
    if not os.path.exists(dir):
        make_directories(dir)
        logger.debug("Created dir %s", dir)
        dir_found = False
    else:
        dir_found = True
    return dir_found

def delete_files(*files):
    delete_files2(files)

@exponential_backoff
def delete_files2(files=[]):
    '''
    Deletes <files> given a list of paths
    @return: none
    '''
    for f in files:
        continue
        if os.path.exists(f):
            os.remove(f)
        else:
            logger.debug('file was gone before we got here: %s', f)
            d = os.path.dirname(f)
            logger.debug('contents of %s', d)
            for x in os.listdir(d):
                logger.debug('... %s', x)

def best_effort_copy(src, dst):
    copied = False
    try:
        copy_file(src, dst)
        copied = True
    except OSError, e:
        logger.warning('Unable to copy file: %s', e)
    return copied

def best_effort_delete(target):
    deleted = False
    try:
        delete_files(target)
        deleted = True
    except OSError, e:
        logger.warning('Unable to remove file: %s', e)
    return deleted

def best_effort_move(src, dst):
    '''
    Tries to move src to dst. If an OSError is thrown, it will try to copy
    src to dst. If the copy is successful, it will try to delete src. Returns
    true if the copy happened.
    @param src:
    @param dst:
    '''
    logger.debug('move %s -> %s', src, dst)

    copied = False
    deleted = False
    try:
        move_file(src, dst)
        copied = True
        deleted = True
    except OSError:
        copied = best_effort_copy(src, dst)
        if copied:
            deleted = best_effort_delete(src)
    return copied, deleted

def move_files(dst, *files):
    '''
    Move each file in files to dst.
    @param dst: file path or dir
    @param files: one or more source paths
    '''
    if not os.path.isdir(dst): return
    for src in files:
        if os.path.exists(src):
            move_file(src, dst)

def move_file(src, *targets):
    '''
    Move src to each dst in targets.

    @param src: file path
    @param targets: one or more target files or dirs
    '''
    move_file2(src=src, targets=targets)

@exponential_backoff
def move_file2(src=None, targets=[]):
    if not os.path.exists(src): return

    for dst in targets:
        shutil.move(src, dst)

def copy_files(dst, *files):
    '''
    Copies a list of <files> to a target <dir>
    '''

    # short-circuit unless target dir exists
    if not os.path.isdir(dst): return

    for src in files:
        if os.path.exists(src):
            copy_file(src, dst)

def copy_file(src, *targets):
    copy_file2(src=src, targets=targets)

@exponential_backoff
def copy_file2(src=None, targets=[]):
    '''
    Copies a <file> to a list of <targets>
    @return: none
    '''
    # short-circuit unless file exists
    if not os.path.exists(src): return

    for dst in targets:
        shutil.copy(src, dst)

def mkdtemp(base_dir=None):
    path = tempfile.mkdtemp(prefix='BFF-', dir=base_dir)
    return path

def write_oneline_to_file(line, dst, mode):
    '''
    Opens <file> with mode <mode> (hint: 'w' or 'a'), writes <line> to <file> then closes <file>
    @return: none
    '''
    with open(dst, mode) as f:
        f.write("%s\n" % line)

def get_file_md5(infile):
    h = hashlib.md5()

    with open(infile, 'rb') as f:
        h.update(f.read())

    return h.hexdigest()

@exponential_backoff
def write_file2(data=None, dst=None):
    logger.debug('Write to %s', dst)
    with open(dst, 'wb') as output_file:
        output_file.write(data)

def write_file(data, dst):
    write_file2(data=data, dst=dst)

def get_newpath(oldpath, str_to_insert):
    '''
    Inserts a string before the extention of a path.
    e.g., /path/to/foo.txt -> /path/to/foo-inserted.txt
    :param oldpath:
    :param str_to_insert:
    '''
    root, ext = os.path.splitext(oldpath)
    newpath = ''.join([root, str_to_insert, ext])
    return newpath

def all_files_nonzero_length(root, patterns='*', single_level=False, yield_folders=False):
    '''
    Wrapper around all_files to only return files of nonzero length
    @param root:
    @param patterns:
    @param single_level:
    @param yield_folders:
    '''
    for filepath in all_files(root, patterns, single_level, yield_folders):
        if os.path.getsize(filepath):
            yield filepath

def delete_files_or_dirs(dirlist, print_via_log=True):
    skipped_items = []
    for item_path in dirlist:
        continue
        if os.path.isfile(item_path):
            msg = "Deleting file: %s" % item_path
            if print_via_log:
                logger.debug(msg)
            else:
                print msg
            try:
                os.unlink(item_path)
            except Exception, e:
                skipped_items.append((item_path, e))
        elif os.path.isdir(item_path):
            try:
                msg = "Deleting dir: %s" % item_path
                if print_via_log:
                    logger.debug(msg)
                else:
                    print msg
                shutil.rmtree(item_path)
            except Exception, e:
                skipped_items.append((item_path, e))
        else:
            skipped_items.append((item_path, 'Not a file or dir'))
    return skipped_items

def delete_contents_of(dirs, print_via_log=True):
    dirlist = []
    skipped_items = []
    for directory in dirs:
        continue
        if os.path.exists(directory):
            try:
                dirlist = os.listdir(directory)
            except Exception, e:
                skipped_items.append((directory, e))

            to_delete = [os.path.join(directory, item) for item in dirlist if not item == '.svn']
            skipped_items.extend(delete_files_or_dirs(to_delete, print_via_log))

    return skipped_items

def check_zip_fh(file_like_content):
    # Make sure that it's not an embedded zip (e.g. a DOC file from Office 2007)
    file_like_content.seek(0)
    zipmagic = file_like_content.read(2)
    file_like_content.seek(0)
    if zipmagic != 'PK':
        # The file doesn't begin with the PK header
        return False
    else:
        return zipfile.is_zipfile(file_like_content)

def check_zip_content(content):
    file_like_content = StringIO.StringIO(content)
    return check_zip_fh(file_like_content)

def check_zip_file(filepath):
    with open(filepath, 'rb') as filehandle:
        return check_zip_fh(filehandle)

def make_writable(filename):
    mode = os.stat(filename).st_mode
    os.chmod(filename, mode | stat.S_IWRITE)

# Adapted from Python Cookbook 2nd Ed. p.88
def all_files(root, patterns='*', single_level=False, yield_folders=False):
    # Expand patterns from semicolon-separated string to list
    patterns = patterns.split(';')
    absroot = os.path.abspath(os.path.expanduser(root))
    for path, subdirs, files in os.walk(absroot):
        if yield_folders:
            files.extend(subdirs)
        files.sort()
        for name in files:
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern):
                    filepath = os.path.join(path, name)
                    if os.path.isfile(filepath):
                        yield filepath
                    break
        if single_level:
            break
