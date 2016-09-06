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
Created on Feb 8, 2012

@organization: cert.org
'''

__version__ = '2.1'

import sys
import logging
import os
from optparse import OptionParser

from certfuzz.campaign.campaign import WindowsCampaign
from logging.handlers import RotatingFileHandler

def _setup_logging_to_screen(options, logger, fmt):
    # logging to screen
    hdlr = logging.StreamHandler()
    hdlr.setFormatter(fmt)
    hdlr.setLevel(logging.INFO)
    # override if debug or quiet
    if options.debug:
        hdlr.setLevel(logging.DEBUG)
    elif options.quiet and not options.verbose:
        hdlr.setLevel(logging.WARNING)
    logger.addHandler(hdlr)

def _setup_logging_to_file(options, logger, fmt):
    # logging to file
    # override if option specified
    if options.logfile:
        logfile = options.logfile
    else:
        logfile = os.path.join('log', 'foe2log.txt')

    hdlr = RotatingFileHandler(logfile, mode='w', maxBytes=1e7, backupCount=5)

    hdlr.setFormatter(fmt)
    hdlr.setLevel(logging.WARNING)
    # override if debug
    if options.debug:
        hdlr.setLevel(logging.DEBUG)
    elif options.verbose:
        hdlr.setLevel(logging.INFO)
    logger.addHandler(hdlr)

def setup_logging(options):
    logger = logging.getLogger()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')
    _setup_logging_to_screen(options, logger, fmt)
    _setup_logging_to_file(options, logger, fmt)
    return logger

def parse_options():
    u = '%prog [options]'
    v = ' '.join(['%prog', 'v%s' % __version__])
    parser = OptionParser(usage=u, version=v)
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages to screen and log file (overrides --quiet)')
    parser.add_option('-q', '--quiet', dest='quiet', action='store_true',
                      help='Silence messages to screen (log file will remain at INFO level')
    parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                      help='Enable verbose logging messages to screen and log file (overrides --quiet)')
    parser.add_option('-c', '--config', dest='configfile', help='Path to config file', 
                      default='configs/foe.yaml', metavar='FILE')
    parser.add_option('-l', '--logfile', dest='logfile', help='Path to log file', metavar='FILE')
    parser.add_option('-r', '--result-dir', dest='resultdir', help='Path to result directory (overrides config)', metavar='DIR')

    (options, args) = parser.parse_args()

    return options, args

def setup_debugging(logger):
    logger.debug('Instantiating embedded rpdb2 debugger with password "foe"...')
    try:
        import rpdb2
        rpdb2.start_embedded_debugger("foe", timeout=0.0)
    except ImportError:
        logger.debug('Error importing rpdb2. Is Winpdb installed?')

    logger.debug('Enabling heapy remote monitoring...')
    try:
        from guppy import hpy  # @UnusedImport
        import guppy.heapy.RM  # @UnusedImport
    except ImportError:
        logger.debug('Error importing heapy. Is Guppy-PE installed?')

def main():
    # parse command line
    options, args = parse_options()

    # start logging
    logger = setup_logging(options)
    logger.info('Welcome to %s version %s', sys.argv[0], __version__)
    for a in args:
        logger.warning('Ignoring unrecognized argument: %s', a)

    if options.debug:
        setup_debugging(logger)

    with WindowsCampaign(config_file=options.configfile, result_dir=options.resultdir, debug=options.debug) as campaign:
        logger.info('Initiating campaign')
        campaign.go()

    logger.info('Campaign complete')

if __name__ == '__main__':
    main()
