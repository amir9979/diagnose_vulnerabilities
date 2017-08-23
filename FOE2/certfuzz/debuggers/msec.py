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

"""This module runs cdb on a process and !exploitable on any exceptions.
"""
import ctypes
from pprint import pformat
from threading import Timer
from subprocess import Popen
import os
import logging
import wmi
import time
import tracing.ida.ida

from . import Debugger as DebuggerBase
from .registration import register
from .output_parsers.msec_file import MsecFile
from ..helpers import check_os_compatibility

logger = logging.getLogger(__name__)

check_os_compatibility('Windows', __name__)

def factory(options):
    return MsecDebugger(options)

class MsecDebugger(DebuggerBase):
    _platform = 'Windows'
    _key = 'msec'
    _ext = 'msec'

    def __init__(self, program, cmd_args, outfile_base, timeout, killprocname, watchcpu, exception_depth=0, **options):
        super(MsecDebugger, self).__init__(program, cmd_args, outfile_base, timeout, killprocname, **options)
        self.exception_depth = exception_depth
        self.watchcpu = watchcpu

    def kill(self, pid, returncode):
        """kill function for Win32"""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(1, 1, pid)
        ret = kernel32.TerminateProcess(handle, returncode)
        kernel32.CloseHandle(handle)
        return (0 != ret)

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        typical = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"
        if os.path.exists(typical):
            return typical
        return 'cdb'

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        return [self.debugger_app(), '-version']

    def _get_cmdline(self, outfile):
        cdb_command = '.load msec;!exploitable -v'
        args = []
        args.append(self.debugger_app())
        args.append('-amsec.dll')
        if hasattr(self, 'debugheap') and self.debugheap:
            # do not use hd, xd options if debugheap is set
            pass
        else:
            args.extend(('-hd', '-xd', 'gp'))
        args.extend(('-logo', outfile))
        args.extend(('-o', '-c'))
        for self.exception_depth in xrange(0, self.exception_depth):
            cdb_command = 'g;' + cdb_command
        tracing.ida.ida.create_bp_script_file(self.binaries_to_diagnose,
                                              cdb_command.split(";"),
                                              self.granularity,
                                              self.tracing_data)
        args.append(tracing.ida.ida.get_append_string(self.granularity))
        args.append(self.program)
        args.extend(self.cmd_args[1:])
        for l in pformat(args).splitlines():
            logger.debug('dbg_args: %s', l)
        return args

    def run_with_timer(self):
        # TODO: replace this with subp.run_with_timer()
        targetdir = os.path.dirname(self.program)
        exename = os.path.basename(self.program)
        process_info = {}
        id = None
        done = False
        started = False
        wmiInterface = None
        retrycount = 0
        foundpid = False

        args = self._get_cmdline(self.outfile)
        print args
        p = Popen(args, stdout=open(os.devnull), stderr=open(os.devnull),
                  cwd=targetdir, universal_newlines=True)

        if self.watchcpu == True:
            wmiInterface = wmi.WMI()
            while retrycount < 5 and not foundpid:
                for process in wmiInterface.Win32_Process(name=exename):
                    # TODO: What if there's more than one?
                    id = process.ProcessID
                    logger.debug('Found %s PID: %s', exename, id)
                    foundpid = True
                if not foundpid:
                    logger.debug('%s not seen yet. Retrying...', exename)
                    retrycount += 1
                    time.sleep(0.1)
            if not id:
                logger.debug('Cannot find %s child process! Bailing.', exename)
                self.kill(p.pid, 99)
                return

        # create a timer that calls kill() when it expires
        print "timer", self.timeout
        t = Timer(self.timeout, self.kill, args=[p.pid, 99])
        t.start()
        if self.watchcpu == True:
            # This is a race.  In some cases, a GUI app could be done before we can even measure it
            # TODO: Do something about it
            while p.poll() is None and not done and id:
                for proc in wmiInterface.Win32_PerfRawData_PerfProc_Process (IDProcess=id):
                    n1, d1 = long (proc.PercentProcessorTime), long (proc.Timestamp_Sys100NS)
                    n0, d0 = process_info.get (id, (0, 0))
                    try:
                        percent_processor_time = (float (n1 - n0) / float (d1 - d0)) * 100.0
                    except ZeroDivisionError:
                        percent_processor_time = 0.0
                    process_info[id] = (n1, d1)
                    logger.debug('Process %s CPU usage: %s', id, percent_processor_time)
                    if percent_processor_time < 0.01:
                        if started:
                            logger.debug('killing %s due to CPU inactivity', p.pid)
                            done = True
                            self.kill(p.pid, 99)
                    else:
                        # Detected CPU usage. Now look for it to drop near zero
                        started = True

                if not done:
                    time.sleep(0.2)
        else:
            p.wait()
        t.cancel()

    def go(self):
        """run cdb and process output"""
        # For exceptions beyond the first one, put the handled exception number in the name
        if self.exception_depth > 0:
            self.outfile = os.path.splitext(self.outfile)[0] + '.e' + str(self.exception_depth) + os.path.splitext(self.outfile)[1]
        self.run_with_timer()
        if not os.path.exists(self.outfile):
            # touch it if it doesn't exist
            open(self.outfile, 'w').close()

        parsed = MsecFile(self.outfile)

        for l in pformat(parsed.__dict__).splitlines():
            logger.debug('parsed: %s', l)
        return parsed
# END MsecDebugger

# register this class as a debugger
register(MsecDebugger)
