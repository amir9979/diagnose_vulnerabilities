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
Created on Jan 17, 2012

Provides the ABRTfile class for analyzing ABRT output.

@organization: cert.org
'''
import re
import logging
from . import regex as regex_base
from . import DebuggerFile

from optparse import OptionParser

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# registers = debug_file.registers

# copy regexes
regex = dict(regex_base)
regex.update({
        'innermost_frame': re.compile(r'^#0.+'),
        'bt_threads': re.compile(r'^\[New Thread.+'),
        'libc_location': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+Yes\s.+/libc[-.]'),
        'mapped_frame': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+Yes\s.+(/.+)'),
         })

class ABRTfile(DebuggerFile):
    def __init__(self, path, exclude_unmapped_frames=True):
        self.has_threads = False
        self.crashing_frame = ''
        self.crashing_thread = False
        self.has_proc_map = False

        super(self.__class__, self).__init__(path, exclude_unmapped_frames)

    def backtrace_line(self, idx, l):
        self._look_for_crashing_thread(l)
        m = re.match(regex['bt_line'], l)
        if m and self.crashing_thread:
            item = m.group(1)  # sometimes gdb splits across lines
            # so get the next one if it looks like '<anything> at <foo>' or '<anything> from <foo>'
            next_idx = idx + 1
            while next_idx < len(self.lines):
                nextline = self.lines[next_idx]
                if re.match(regex['bt_line_basic'], nextline):
                    break
                elif re.search(regex['bt_line_from'], nextline) or re.search(regex['bt_line_at'], nextline):
                    if not "Quit anyway" in nextline:
                        item = ' '.join((item, nextline))
                next_idx += 1

            self.backtrace.append(item)
            logger.debug('Appending to backtrace: %s', item)

    def _process_lines(self):
        logger.debug('_process_lines')

        for idx, line in enumerate(self.lines):

            # Check to see if the input data has threads
            if not self.has_threads and not self.crashing_thread:
                self._look_for_threads(line)

            # If there are threads, look to see which crashed
            if not self.crashing_frame and self.has_threads:
                self._look_for_crashing_frame(line)
            # Otherwise, there's just one thread and it's the crashing one
            else:
                self.backtrace_line(idx, line)

            if not self.exit_code:
                self._look_for_exit_code(line)

            if not self.signal:
                self._look_for_signal(line)

            if self.is_crash:
                self._look_for_crash(line)

            if not self.is_debugbuild:
                self._look_for_debug_build(line)

            if not self.is_corrupt_stack:
                self._look_for_corrupt_stack(line)

            if not self.libc_start_addr:
                self._look_for_libc_location(line)

            if not self.has_proc_map:
                self._look_for_proc_map(line)

            self._look_for_registers(line)
            self._build_module_map(line)

        self._process_backtrace()

    def _look_for_debugger_missed_stack_corruption(self):
        if self.has_proc_map:
            start_bt_length = len(self.backtrace)
            while self.backtrace:
                # If the outermost backtrace frame isn't from a loaded module,
                # then we're likely dealing with stack corruption
                mapped_frame = False

                frame_address = self._get_frame_address(self.backtrace[-1])
                if frame_address:
                    mapped_frame = self._is_mapped_frame(frame_address)
                    if not mapped_frame:
                        self.debugger_missed_stack_corruption = True
                        # we can't use this line in a backtrace, so pop it
                        removed_bt_line = self.backtrace.pop()
                        logger.debug("GDB missed corrupt stack detection. Removing backtrace line: %s", removed_bt_line)
                    else:
                        # as soon as we hit a line that is a mapped
                        # frame, we're done trimming the backtrace
                        break
                else:
                    # if the outermost frame of the backtrace doesn't list a memory address,
                    # it's likely main(), which is fine.
                    break

            end_bt_length = len(self.backtrace)

            if start_bt_length and not end_bt_length:
                # Destroyed ALL the backtrace!
                self.total_stack_corruption = True
                logger.debug('Total stack corruption. No backtrace lines left.')
        else:
            logger.debug('No proc map available.  Cannot check for stack corruption')

    def _look_for_crashing_frame(self, line):
        m = re.match(regex['innermost_frame'], line)
        if m:
            self.crashing_frame = line
            logger.debug('Crashing frame: %s', self.crashing_frame)

    def _look_for_threads(self, line):
        logger.debug('Looking for threads...')
        m = re.match(regex['bt_threads'], line)
        if m:
            self.has_threads = True
            logger.debug('Threads detected')

    def _look_for_crashing_thread(self, line):
        m = re.match(regex['innermost_frame'], line)
        if m and self.crashing_frame in line:
            self.crashing_thread = True
            logger.debug('Found crashing thread!')
        elif m and self.has_threads:
            self.crashing_thread = False
        elif m:
            self.crashing_thread = True
            logger.debug('No threads in this data...')

    def _look_for_proc_map(self, line):
        '''
        Check to see if the input file has proc map information
        '''
        m = re.match(regex['mapped_frame'], line)
        if m:
            logger.debug('Found proc map information')
            # self.has_proc_map = True
            # Currently disabling proc map assisted parsing.  ABRT reports don't contain
            # the map for the current process.  Only loaded libraries!
            self.has_proc_map = False
        else:
            self.exclude_unmapped_frames = False

if __name__ == '__main__':
    # override the module loger with the root logger
    logger = logging.getLogger()

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true', help='Enable verbose messages')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    for f in args:
        a = ABRTfile(f)
        print 'Signature=%s' % a.get_crash_signature(5)
        if a.registers_hex.get('eip'):
            print 'EIP=%s' % a.registers_hex['eip']
