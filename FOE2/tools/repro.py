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
Created on Feb 4, 2013

@organization: cert.org
'''
import logging
import os
import string
import re
from subprocess import Popen

try:
    from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
    from certfuzz import debuggers
    from certfuzz.file_handlers.basicfile import BasicFile
    from certfuzz.runners.runner_base import get_command_args_list
    from certfuzz.campaign.config.foe_config import Config
    from certfuzz.debuggers import msec  # @UnusedImport
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    import sys
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
    from certfuzz import debuggers
    from certfuzz.file_handlers.basicfile import BasicFile
    from certfuzz.runners.runner_base import get_command_args_list
    from certfuzz.campaign.config.foe_config import Config
    from certfuzz.debuggers import msec  # @UnusedImport

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

def parseiterpath(commandline):
    # Return the path to the iteration's fuzzed file
    for part in commandline.split():
        if 'foe-crash-' in part:
            return part

def getiterpath(msecfile):
    # Find the commandline in an msec file
    with open(msecfile) as mseclines:
        for line in mseclines:
            m = re.match('CommandLine: ', line)
            if m:
                return parseiterpath(line)

def main():
    debuggers.verify_supported_platform()

    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    usage = "usage: %prog [options] fuzzedfile"
    parser = OptionParser(usage)
    parser.add_option('', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true',
                      help='Enable verbose messages')
    parser.add_option('-c', '--config', default='configs/foe.yaml',
                      dest='config',
                      help='path to the configuration file to use')
    parser.add_option('-w', '--windbg', dest='use_windbg',
                      action='store_true',
                      help='Use windbg instead of cdb')
    parser.add_option('-b', '--break', dest='break_on_start',
                      action='store_true',
                      help='Break on start of debugger session')
    parser.add_option('-d', '--debugheap', dest='debugheap',
                      action='store_true',
                      help='Use debug heap')
    parser.add_option('-p', '--debugger', dest='debugger',
                      help='Use specified debugger')
    parser.add_option('-f', '--filepath', dest='filepath',
                      action='store_true', help='Recreate original file path')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    cfg_file = options.config
    logger.debug('Config file: %s', cfg_file)

    if len(args) and os.path.exists(args[0]):
        fullpath_fuzzed_file = os.path.abspath(args[0])
        fuzzed_file = BasicFile(fullpath_fuzzed_file)
        logger.info('Fuzzed file is %s', fuzzed_file)
    else:
        parser.error('fuzzedfile must be specified')

    config = Config(cfg_file).config

    iterationpath = ''
    template = string.Template(config['target']['cmdline_template'])
    if options.filepath:
        # Recreate same file path as fuzz iteration
        resultdir = os.path.dirname(fuzzed_file.path)
        for msecfile in all_files(resultdir, '*.msec'):
            print '** using msecfile: %s' % msecfile
            iterationpath = getiterpath(msecfile)
            break

        if iterationpath:
            iterationdir = os.path.dirname(iterationpath)
            iterationfile = os.path.basename(iterationpath)
            mkdir_p(iterationdir)
            copy_file(fuzzed_file.path,
                      os.path.join(iterationdir, iterationfile))
            fuzzed_file.path = iterationpath

    cmd_as_args = get_command_args_list(template, fuzzed_file.path)[1]
    targetdir = os.path.dirname(cmd_as_args[0])

    args = []

    if options.use_windbg and options.debugger:
        parser.error('Options --windbg and --debugger are mutually exclusive.')

    if options.debugger:
        debugger_app = options.debugger
    elif options.use_windbg:
        debugger_app = 'windbg'
    else:
        debugger_app = 'cdb'

    args.append(debugger_app)

    if not options.debugger:
        # Using cdb or windbg
        args.append('-amsec.dll')
        if options.debugheap:
            # do not use hd, xd options if debugheap is set
            pass
        else:
            args.extend(('-hd', '-xd', 'gp'))
        if not options.break_on_start:
            args.extend(('-xd', 'bpe', '-G'))
        args.extend(('-xd', 'wob', '-o',))
    args.extend(cmd_as_args)
    logger.info('args %s' % cmd_as_args)

    p = Popen(args, cwd=targetdir, universal_newlines=True)
    p.wait()

if __name__ == '__main__':
    main()
