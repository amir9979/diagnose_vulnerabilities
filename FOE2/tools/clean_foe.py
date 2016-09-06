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
Created on Feb 28, 2012

@author: adh
'''

import os
import time
import tempfile
import pprint

defaults = {'config': 'configs/foe.yaml',
            'remove_results': False,
            'pretend': False,
            'retry': 3,
            'debug': False,
            'nuke': False,
          }

SLEEPTIMER = 0.5
BACKOFF_FACTOR = 2

if __name__ == '__main__':
    import optparse
    try:
        from certfuzz.fuzztools.filetools import delete_contents_of
        from certfuzz.campaign.config import Config
    except ImportError:
        # if we got here, we probably don't have .. in our PYTHONPATH
        import sys
        mydir = os.path.dirname(os.path.abspath(__file__))
        parentdir = os.path.abspath(os.path.join(mydir, '..'))
        sys.path.append(parentdir)
        from certfuzz.fuzztools.filetools import delete_contents_of
        from certfuzz.campaign.config import Config
        if not os.path.exists(defaults['config']):
            defaults['config'] = '../configs/foe.yaml'

    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest='configfile', default=defaults['config'], metavar='FILE')
    parser.add_option('-p', '--pretend', dest='pretend', action='store_true', default=defaults['pretend'], help='Do not actually remove files')
    parser.add_option('-r', '--retry', dest='retries', default=defaults['retry'], type='int', metavar='INT')
    parser.add_option('', '--remove-results', dest='remove_results', action='store_true', default=defaults['remove_results'], help='Removes results dir contents')
    parser.add_option('', '--all', dest='nuke', action='store_true', default=defaults['nuke'], help='Equivalent to --remove-results')
    parser.add_option('', '--debug', dest='debug', action='store_true', default=defaults['debug'])
    options, args = parser.parse_args()

    cfgobj = Config(options.configfile)
    c = cfgobj.config

    if options.debug:
        pprint.pprint(c)

    dirs = set()

    if options.nuke:
        options.remove_results = True

    dirs.add(os.path.abspath(c['directories']['working_dir']))
    dirs.add(os.path.join(os.path.abspath(c['directories']['results_dir']), c['campaign']['id'], 'seedfiles'))
    if options.remove_results:
        dirs.add(os.path.join(os.path.abspath(c['directories']['results_dir']), c['campaign']['id'],))

    # add temp dir(s) if available
    if tempfile.gettempdir().lower() != os.getcwd().lower():
        # Only add tempdir if it's valid.  Otherwise you get cwd
        dirs.add(tempfile.gettempdir())
    try:
        dirs.add(os.environ['TMP'])
    except KeyError:
        pass

    try:
        dirs.add(os.environ['TEMP'])
    except KeyError:
        pass

    if not options.pretend:
        tries = 0
        done = False
        skipped = []
        while not done:
            skipped = delete_contents_of(dirs, print_via_log=False)
            # if we got here, no exceptions were thrown
            # so we're done
            if skipped:
                if tries < options.retries:
                    # typically exceptions happen because the OS hasn't
                    # caught up with file lock status, so give it a chance
                    # to do so before the next iteration
                    nap_length = SLEEPTIMER * pow(BACKOFF_FACTOR, tries)
                    tries += 1
                    print '%d files skipped, waiting %0.1fs to retry (%d of %d)' % (len(skipped), nap_length, tries, options.retries)
                    time.sleep(nap_length)
                else:
                    print 'Maximum retries (%d) exceeded.' % options.retries
                    done = True
            else:
                done = True

        for (skipped_item, reason) in skipped:
            print "Skipped file %s: %s" % (skipped_item, reason)

    else:
        parser.print_help()
        print
        print 'Would have deleted the contents of:'
        for d in dirs:
            print '... %s' % d
