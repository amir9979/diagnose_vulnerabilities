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
Created on Oct 11, 2012

@organization: cert.org
'''
import logging
import os
import tempfile
import time
import numpy
import shutil
import random
import hashlib
import itertools

from .. import debuggers
from ..fuzztools import hamming, filetools, probability, text
from ..fuzztools.filetools import delete_files, write_file
from ..file_handlers.basicfile import BasicFile
from ..file_handlers.tmp_reaper import TmpReaper
from .errors import MinimizerError

try:
    from ..analyzers import pin_calltrace
    from ..analyzers import AnalyzerEmptyOutputError
    from ..debuggers.output_parsers.calltracefile import Calltracefile
except ImportError:
    pass

logger = logging.getLogger(__name__)

# if len(self.other_crashes) exceeds this number, we're
# going to abort the minimization early
MAX_OTHER_CRASHES = 20

class Minimizer:
    use_watchdog = False

    def __init__(self, cfg=None, crash=None, crash_dst_dir=None,
                 seedfile_as_target=False, bitwise=False, confidence=0.999,
                 logfile=None, tempdir=None, maxtime=3600, preferx=False, keep_uniq_faddr=False, watchcpu=False):

        if not cfg:
            raise MinimizerError('Config must be specified')
        if not crash:
            raise MinimizerError('Crasher must be specified')

        self.cfg = cfg
        self.crash = crash
        self.seedfile_as_target = seedfile_as_target
        self.bitwise = bitwise
        self.preferx = preferx
        self.max_time = maxtime
        # if max_time is not positive, assume that we don't
        # want to time out ever
        self.use_timer = maxtime > 0.0
        self.start_time = 0.0
        self.keep_uniq_faddr = keep_uniq_faddr
        self.watchcpu = watchcpu

        self.minchar = 'x'
        self.save_others = True
        self.ext = self.crash.fuzzedfile.ext
        self.logger = None
        self.log_file_hdlr = None

        logger.setLevel(logging.INFO)

        if tempdir and os.path.isdir(tempdir):
            self.tempdir = tempfile.mkdtemp(prefix='minimizer_', dir=tempdir)
        else:
            self.tempdir = tempfile.mkdtemp(prefix='minimizer_')

        logger.debug('Minimizer tempdir is %s', self.tempdir)

        # decide whether we're doing a bitwise comparison or bytewise
        if self.bitwise:
            self.hd_func = hamming.bitwise_hd
            self.swap_func = self.bitwise_swap2
        else:
            self.hd_func = hamming.bytewise_hd
            self.swap_func = self.bytewise_swap2

        if self.seedfile_as_target:
            minf = '%s-minimized%s' % (self.crash.fuzzedfile.root, self.crash.fuzzedfile.ext)
            minlog = os.path.join(self.crash.fuzzedfile.dirname, 'minimizer_log.txt')
            if not os.path.exists(self.crash.seedfile.path):
                raise MinimizerError('Seedfile not found at %s' %
                                     self.crash.seedfile.path)
        elif self.preferx:
            minf = '%s-min-%s%s' % (self.crash.fuzzedfile.root, self.minchar, self.crash.fuzzedfile.ext)
            minlog = os.path.join(self.crash.fuzzedfile.dirname, 'minimizer_%s_log.txt' % self.minchar)
        else:
            minf = '%s-min-mtsp%s' % (self.crash.fuzzedfile.root, self.crash.fuzzedfile.ext)
            minlog = os.path.join(self.crash.fuzzedfile.dirname, 'minimizer_mtsp_log.txt')

        self.outputfile = os.path.join(self.crash.fuzzedfile.dirname, minf)

        if logfile:
            self.minimizer_logfile = logfile
        else:
            self.minimizer_logfile = minlog

        if crash_dst_dir:
            self.crash_dst = crash_dst_dir
        else:
            self.crash_dst = self.crash.fuzzedfile.dirname

        if not os.path.exists(self.crash_dst):
            raise MinimizerError("%s does not exist" % self.crash_dst)
        if not os.path.isdir(self.crash_dst):
            raise MinimizerError("%s is not a directory" % self.crash_dst)

        self.debugger = debuggers.get()

        self._logger_setup()
        self.logger.info("Minimizer initializing for %s", self.crash.fuzzedfile.path)

        if not os.path.exists(self.crash.fuzzedfile.path):
            raise MinimizerError("%s does not exist" % self.crash.fuzzedfile.path)

        self.crash.set_debugger_template('bt_only')

        self.other_crashes = {}
        self.target_size_guess = 1
        self.total_tries = 0
        self.total_misses = 0
        self.consecutive_misses = 0
        self.discard_chance = 0
        self.debugger_runs = 0
        self.min_found = False
        self.confidence_level = confidence
        self.newfuzzed_hd = 0
        self.newfuzzed_md5 = None
        self.n_misses_allowed = 0
        self.newfuzzed = ''

        self.crash_sigs_found = {}
        self.files_tried = {}
        self.files_tried_at_hd = {}
        self.files_tried_singlebyte_at_hd = {}
        self.bytemap = []
#         self.saved_arcinfo = {}
#         self.is_zipfile = False

#         self.is_zipfile = self.check_zipfile(self.crash.fuzzedfile.path)

        self.fuzzed = self._read_fuzzed()
        self.seed = self._read_seed()

        # none of this will work if the files are of different size
        if len(self.seed) != len(self.fuzzed):
            raise MinimizerError('Minimizer requires seed and fuzzed to have the same length. %d != %d' % (len(self.seed), len(self.fuzzed)))

        # initialize the hamming distance
        self.start_distance = self.hd_func(self.seed, self.fuzzed)
        self.min_distance = self.start_distance

        # some programs crash differently depending on where the
        # file is loaded from. So we'll reuse this file name for
        # everything
        f = tempfile.NamedTemporaryFile('wb', delete=True,
                                        dir=self.tempdir,
                                        prefix="minimizer_fuzzed_file_",
                                        suffix=self.crash.fuzzedfile.ext)
        # since we set delete=True, f will be deleted on close,
        # which makes it available to us to reuse
        f.close()
        self.tempfile = f.name
        filetools.copy_file(self.crash.fuzzedfile.path, self.tempfile)

        # figure out what crash signatures belong to this fuzzedfile
        self.debugger_timeout = self.cfg.debugger_timeout
        self.crash_hashes = []
        self.measured_dbg_time = None
        self._set_crash_hashes()

        # set the debugger_timeout to the lesser of what we've measured
        # in getting the crash_hashes or what it already was
        if self.measured_dbg_time:
            self.debugger_timeout = min(self.debugger_timeout, self.measured_dbg_time)

        self.logger.info('\tusing debugger timeout: %0.5f', self.debugger_timeout)
        self.logger.info('\tconfidence level: %0.5f', self.confidence_level)
        self.logger.info('\tstarting Hamming Distance is %d', self.start_distance)

    def __enter__(self):
        # make sure we can actually minimize
        if not self._is_crash_to_minimize():
            msg = 'Unable to minimize: No crash'
            self.logger.info(msg)
            raise MinimizerError(msg)
        if self._is_already_minimized():
            msg = 'Unable to minimize: Already minimized'
            self.logger.info(msg)
            raise MinimizerError(msg)
        if self.crash.debugger_missed_stack_corruption:
            msg = 'Unable to minimize: Stack corruption crash, which the debugger missed.'
            self.logger.info(msg)
            raise MinimizerError(msg)
        # start the timer
        self.start_time = time.time()
        return self

    def __exit__(self, etype, value, traceback):
        self.log_file_hdlr.close()
        self.logger.removeHandler(self.log_file_hdlr)
        if not etype:
            # clean exit, clean up
            filetools.delete_files_or_dirs([self.tempdir])
        # remove the watchdog file
#        try:
#            os.remove(self.cfg.watchdogfile)
#        except IOError:
#            # it's okay if we can't
#            pass

    def _read_fuzzed(self):
        '''
        returns the contents of the fuzzed file
        '''
        return self.crash.fuzzedfile.read()

    def _read_seed(self):
        '''
        returns the contents of the seed file
        '''
    # we're either going to minimize to the seedfile, the metasploit pattern, or a string of 'x's
        if self.seedfile_as_target:
                return self.crash.seedfile.read()
        elif self.preferx:
            return self.minchar * len(self.fuzzed)
        else:
            return text.metasploit_pattern_orig(len(self.fuzzed))

    def _logger_setup(self):
        dirname = os.path.dirname(self.minimizer_logfile)

        if not os.path.exists(dirname):
            raise MinimizerError('Directory should already exist: %s' % dirname)
        if os.path.exists(self.minimizer_logfile):
            raise MinimizerError('Log file must not already exist: %s' % self.minimizer_logfile)
        self.logger = logging.getLogger(__name__)
        self.log_file_hdlr = logging.FileHandler(self.minimizer_logfile)
        self.logger.addHandler(self.log_file_hdlr)

    def _set_crash_hashes(self):
        if not self.crash_hashes:
            miss_count = 0
            # we want to keep going until we are 0.95 confident that
            # if there are any other crashers they have a probability
            # less than 0.5
            max_misses = probability.misses_until_quit(0.95, 0.5)
            sigs_seen = {}
            times = []
            # loop until we've found ALL the crash signatures
            while miss_count < max_misses:
                # (sometimes crash sigs change for the same input file)
                (fd, f) = tempfile.mkstemp(prefix='minimizer_set_crash_hashes_', text=True, dir=self.tempdir)
                os.close(fd)
                delete_files(f)

                # run debugger
                start = time.time()

                dbg = self.run_debugger(self.tempfile, f)

                # remember the elapsed time for later
                end = time.time()
                delta = end - start
                if dbg.is_crash:
                    times.append(delta)

                current_sig = self.get_signature(dbg, self.cfg.backtracelevels)

                # ditch the temp file
                if os.path.exists(f):
                    delete_files(f)

                if current_sig:
                    if sigs_seen.get(current_sig):
                        sigs_seen[current_sig] += 1
                        miss_count += 1
                    else:
                        sigs_seen[current_sig] = 1
                        miss_count = 0
                else:
                    # this crash had no signature, so skip it
                    miss_count += 1
            self.crash_hashes = sigs_seen.keys()
            # calculate average time
            # get stdev
            avg_time = numpy.average(times)
            stdev_time = numpy.std(times)
            # set debugger timeout to 0.95 confidence
            # TODO: What if the VM becomes slower.
            # We may give up on crashes before they happen.
            zscore = 1.645
            self.measured_dbg_time = avg_time + (zscore * stdev_time)

        return self.crash_hashes

    def run_debugger(self, infile, outfile):
        self.debugger_runs += 1
        cmd_args = self.cfg.get_command_args_list(infile)

        dbg = self.debugger(self.cfg.program,
                            cmd_args,
                            outfile,
                            self.debugger_timeout,
                            self.cfg.killprocname,
                            template=self.crash.debugger_template,
                            exclude_unmapped_frames=self.cfg.exclude_unmapped_frames,
                            keep_uniq_faddr=self.keep_uniq_faddr,
                            workingdir=self.tempdir,
                            watchcpu=self.watchcpu
                            )
        parsed_debugger_output = dbg.go()
        return parsed_debugger_output

    def _crash_builder(self):
        self.logger.debug('Building new crash object.')
        import copy

        # copy our original crash as the basis for the new crash
        newcrash = copy.copy(self.crash)

        # get a new dir for the next crasher
        newcrash_tmpdir = tempfile.mkdtemp(prefix='minimizer_crash_builder_', dir=self.tempdir)

        # get a new filename for the next crasher
        sfx = self.crash.fuzzedfile.ext
        if self.crash.seedfile:
            pfx = '%s-' % self.crash.seedfile.root
        else:
            pfx = 'string-'
        (fd, f) = tempfile.mkstemp(suffix=sfx, prefix=pfx, dir=newcrash_tmpdir)
        os.close(fd)
        delete_files(f)
        outfile = f

        if os.path.exists(outfile):
            raise MinimizerError('Outfile should not already exist: %s' % outfile)
        self.logger.debug('\tCopying %s to %s', self.tempfile, outfile)
        filetools.copy_file(self.tempfile, outfile)

        newcrash.fuzzedfile = BasicFile(outfile)
        self.logger.debug('\tNew fuzzed file: %s %s', newcrash.fuzzedfile.path, newcrash.fuzzedfile.md5)

        # clear out the copied crash signature so that it will be regenerated
        newcrash.signature = None

        # replace old crash details with new info specific to this crash
        self.logger.debug('\tUpdating crash details')
        newcrash.update_crash_details()

        # the tempdir we created is no longer needed because update_crash_details creates a fresh one
        shutil.rmtree(newcrash_tmpdir)
        if os.path.exists(newcrash_tmpdir):
            logger.warning("Failed to remove temp dir %s", newcrash_tmpdir)

        return newcrash

    def get_signature(self, dbg, backtracelevels):
        signature = dbg.get_crash_signature(backtracelevels)
        if dbg.total_stack_corruption:
            # total_stack_corruption.  Use pin calltrace to get a backtrace
            analyzer_instance = pin_calltrace.Pin_calltrace(self.cfg, self.crash)
            try:
                analyzer_instance.go()
            except AnalyzerEmptyOutputError:
                logger.warning('Unexpected empty output from analyzer. Continuing')
            if os.path.exists(analyzer_instance.outfile):
                calltrace = Calltracefile(analyzer_instance.outfile)
                pinsignature = calltrace.get_crash_signature(backtracelevels * 10)
                if pinsignature:
                    signature = pinsignature
        return signature

    def is_same_crash(self):

        # get debugger output filename
        (fd, f) = tempfile.mkstemp(dir=self.tempdir, prefix="minimizer_is_same_crash_")
        os.close(fd)
        if os.path.exists(f):
            delete_files(f)
        if os.path.exists(f):
            raise MinimizerError('Unable to get temporary debug file')

        # create debugger output
        dbg = self.run_debugger(self.tempfile, f)

        if dbg.is_crash:
            newfuzzed_hash = self.get_signature(dbg, self.cfg.backtracelevels)
        else:
            newfuzzed_hash = None
        # initialize or increment the counter for this hash
        if newfuzzed_hash in self.crash_sigs_found:
            self.crash_sigs_found[newfuzzed_hash] += 1
        elif not newfuzzed_hash:
            # don't do anything with non-crashes
            pass
        else:
            # the crash is new to this minimization run
            self.crash_sigs_found[newfuzzed_hash] = 1
            self.logger.info('crash=%s signal=%s', newfuzzed_hash, dbg.signal)

            if self.save_others and not newfuzzed_hash in self.crash_hashes:
                # the crash is not one of the crashes we're looking for
                # so add it to the other_crashes dict in case our
                # caller wants to do something with it
                newcrash = self._crash_builder()
                if newcrash.is_crash:
                    # note that since we're doing this every time we see a crash
                    # that's not in self.crash_hashes, we're also effectively
                    # keeping only the smallest hamming distance version of
                    # newfuzzed_hash as we progress through the minimization process
                    self.other_crashes[newfuzzed_hash] = newcrash

        # ditch the temp file
        delete_files(dbg.file)
        if os.path.exists(dbg.file):
            raise MinimizerError('Unable to remove temporary debug file')

        return newfuzzed_hash in self.crash_hashes

    def set_discard_chance(self):
        new_dc = 1.0 / (self.target_size_guess + 1.0)
        min_dc = 1.0 - float(self.target_size_guess) / float(self.min_distance)

        # if there aren't any discard chances left, we're done
        if new_dc >= min_dc:
            return False

        # if we're changing the discard chance, reset the consecutive miss count
        if not self.discard_chance == new_dc:
            self.consecutive_misses = 0
            self.discard_chance = new_dc

        return True

    def set_n_misses(self):
        # don't do anything if we already found a minimum
        if self.min_found:
            return False

        keep_chance = 1.0 - self.discard_chance
        p = probability.FuzzRun(self.min_distance, self.target_size_guess, keep_chance)

        self.n_misses_allowed = p.how_many_misses_until_quit(self.confidence_level)
        return True

    def have_we_seen_this_file_before(self):
        # is this a new file?
        if not self.files_tried.get(self.newfuzzed_md5):
            # totally new file
            self.files_tried[self.newfuzzed_md5] = 1
            return False

        # it's a repeat
        self.files_tried[self.newfuzzed_md5] += 1
        return True

    def print_intermediate_log(self):
        if not self.newfuzzed_hd:
            self.logger.debug('self.newfuzzed_hd not set. Default to self.min_distance')
            new_hd = self.min_distance
        else:
            new_hd = self.newfuzzed_hd

        if not self.n_misses_allowed:
            self.logger.debug('self.n_misses_allowed not set. Default to self.consecutive_misses')
            n_misses_allowed = self.consecutive_misses
        else:
            n_misses_allowed = self.n_misses_allowed

        parts = []
        parts.append('start=%d' % self.start_distance)
        parts.append('min=%d' % self.min_distance)
        parts.append('target_guess=%d' % self.target_size_guess)
        parts.append('curr=%d' % new_hd)
        parts.append('chance=%0.5f' % self.discard_chance)
        parts.append('miss=%d/%d' % (self.consecutive_misses, n_misses_allowed))
        parts.append('total_misses=%d/%d' % (self.total_misses, self.total_tries))
        parts.append('u_crashes=%d' % len(self.crash_sigs_found.items()))
        logstring = ' '.join(parts)
        self.logger.info(logstring)

    def _crash_hashes_string(self):
        return ', '.join(self.crash_hashes)

    def _is_crash_to_minimize(self):
        return len(self.crash_hashes) > 0

    def _is_already_minimized(self):
        return self.min_distance <= 1

    def _time_exceeded(self):
        time_now = time.time()
        elapsed_time = time_now - self.start_time
        # return false if:
        # (1) we're not using the timer (max_time <= 0)
        # (2) we are using the timer but it hasn't expired yet
        # otherwise return true
        return(self.use_timer and (elapsed_time > self.max_time))

    def _write_file(self):
        write_file(''.join(self.newfuzzed), self.tempfile)

    def go(self):
        # start by copying the fuzzed file since as of now it's our best fit
        filetools.copy_file(self.crash.fuzzedfile.path, self.outputfile)

        # replace the fuzzedfile object in crash with the minimized copy
        self.crash.fuzzedfile = BasicFile(self.outputfile)

        self.logger.info('Attempting to minimize crash(es) [%s]', self._crash_hashes_string())

        # keep going until either:
        # a. we find a minimum hd of 1
        # b. we run out of discard_chances
        # c. our discard_chance * minimum hd is less than one (we won't discard anything)
        # d. we've exhaustively searched all the possible files with hd less than self.min_distance
        while not self.min_found:

            if not self.set_discard_chance():
                break

            if not self.set_n_misses():
                break

            got_hit = False
            while self.consecutive_misses <= self.n_misses_allowed:
                # clean the /tmp directory so we don't fill up the disk across tries
                TmpReaper().clean_tmp()

                if self.use_watchdog:
                    # touch the watchdog file so we don't reboot during long minimizations
                    open(self.cfg.watchdogfile, 'w').close()

                # Fix for BFF-208
                if self._time_exceeded():
                    logger.info('Max time for minimization exceeded, ending minimizer early.')
                    self.min_found = True
                    break

                if not self.set_discard_chance():
                    break

                if not self.set_n_misses():
                    break

                self.swap_bytes()

                self.total_tries += 1

                is_repeat = self.have_we_seen_this_file_before()

                # have we been at this level before?
                if not self.files_tried_at_hd.get(self.min_distance):
                    # we've reached a new minimum
                    self.files_tried_at_hd[self.min_distance] = {}
                    self.files_tried_singlebyte_at_hd[self.min_distance] = {}

                # have we seen this file at this level before?
                if not self.files_tried_at_hd[self.min_distance].get(self.newfuzzed_md5):
                    # this is a new file so we'll try it
                    self.files_tried_at_hd[self.min_distance][self.newfuzzed_md5] = 1
                    if self.newfuzzed_hd == (self.min_distance - 1):
                        self.files_tried_singlebyte_at_hd[self.min_distance][self.newfuzzed_md5] = 1
                else:
                    # this is a repeat at this level
                    self.files_tried_at_hd[self.min_distance][self.newfuzzed_md5] += 1
                    if self.newfuzzed_hd == (self.min_distance - 1):
                        self.files_tried_singlebyte_at_hd[self.min_distance][self.newfuzzed_md5] += 1

                    # have we exhausted all the possible files with smaller hd?
                    possible_files = (2 ** self.min_distance) - 2
                    seen_files = len(self.files_tried_at_hd[self.min_distance])
                    # maybe we're done?
                    if seen_files == possible_files:
                        # we've exhaustively searched everything with hd < self.min_distance
                        self.logger.info('Exhaustively searched all files shorter than %d', self.min_distance)
                        self.min_found = True
                        break

                    # have we exhausted all files that are 1 byte smaller hd?
                    possible_singlebyte_diff_files = self.min_distance
                    singlebyte_diff_files_seen = len(self.files_tried_singlebyte_at_hd[self.min_distance])
                    # maybe we're done?
                    if singlebyte_diff_files_seen == possible_singlebyte_diff_files:
                        self.logger.info('We have tried all %d files that are one byte closer than the current minimum', self.min_distance)
                        self.min_found = True
                        break

                self.print_intermediate_log()

                if is_repeat:
                    # we've already seen this attempt, so skip ahead to the next one
                    # but still count it as a miss since our math assumes we're putting
                    # the marbles back in the jar after each draw
                    self.consecutive_misses += 1
                    self.total_misses += 1
                    continue

                # we have a better match, write it to a file
                if not len(self.newfuzzed):
                    raise MinimizerError('New fuzzed content is empty.')

                self._write_file()

                if self.is_same_crash():
                    # record the result
                    # 1. copy the tempfile
                    filetools.best_effort_move(self.tempfile, self.outputfile)
                    # 2. replace the fuzzed file in the crasher with the current one
                    self.crash.fuzzedfile = BasicFile(self.outputfile)
                    # 3. replace the current fuzzed with newfuzzed
                    self.fuzzed = self.newfuzzed
                    self.min_distance = self.newfuzzed_hd

                    got_hit = True

                    if self.min_distance == 1:
                        # we are done
                        self.min_found = True
                    else:
                        # set up for next iteration
                        self.consecutive_misses = 0
                        if not self.set_discard_chance():
                            break
                        if not self.set_n_misses():
                            break
                else:
                    # we missed. increment counter and try again
                    self.total_misses += 1
                    self.consecutive_misses += 1

                    # Fix for BFF-225
                    # There may be some situation that causes crash uniqueness
                    # hashing to break. (e.g. BFF-224 ). Minimizer should bail
                    # if the number of unique crashes encountered exceeds some
                    # threshold. e.g. 20 maybe?
                    if len(self.other_crashes) > MAX_OTHER_CRASHES and self.seedfile_as_target:
                        logger.info('Exceeded maximum number of other crashes (%d), ending minimizer early.',
                                    MAX_OTHER_CRASHES)
                        self.min_found = True
                        break

            if not got_hit:
                # we are self.confidence_level sure that self.target_size_guess is wrong
                # so increment it by 1
                self.target_size_guess += 1

        self.print_intermediate_log()

        self.logger.info('We were looking for [%s] ...', self._crash_hashes_string())
        for (md5, count) in self.crash_sigs_found.items():
            self.logger.info('\t...and found %s\t%d times', md5, count)
        if self.fuzzed:
            self.bytemap = hamming.bytemap(self.seed, self.fuzzed)
            self.logger.info('Bytemap: %s', self.bytemap)

    def get_mask(self):
        mask = 0
        for i in range(8):
            if random.random() <= self.discard_chance:
                mask ^= 1 << i
        return mask

    def swap_bytes(self):
        newfuzzed = []
        newfuzzed_hd = self.min_distance

        if not 0.0 < self.discard_chance < 1.0:
            raise MinimizerError("Discard chance out of range")

        # it's possible we could get a zero-distance newfuzz
        # or that we didn't drop any bytes at all
        # so keep trying until both are true
        while not (0 < newfuzzed_hd < self.min_distance):
            newfuzzed, newfuzzed_hd = self.swap_func(self.seed, self.fuzzed)

        # we know our hd is > 0 and < what it was when we started
        self.newfuzzed = newfuzzed
        self.newfuzzed_hd = newfuzzed_hd
        self.newfuzzed_md5 = hashlib.md5(''.join(self.newfuzzed)).hexdigest()

    def bytewise_swap2(self, seed, fuzzed):
        swapped = []
        hd = 0

        # it's a tight loop and we hit it a lot so
        # remove the need to resolve function names
        append = swapped.append
        rand = random.random
        dc = self.discard_chance

        for (a, b) in itertools.izip(seed, fuzzed):
            if a != b and rand() > dc:
                append(b)
                hd += 1
            else:
                append(a)
        return swapped, hd
        # Note that the above implementation is actually faster overall than the list
        # comprehension below since we're catching the hamming distance at the same time.

    def _mask(self):
        mask = 0
        rand = random.random()
        dc = self.discard_chance
        for i in range(8):
            if rand() <= dc:
                mask ^= 1 << i
        return mask

    def bitwise_swap2(self, seed, fuzzed):
        swapped = []
        hd = 0
        for (a, b) in itertools.izip(seed, fuzzed):
            if a != b:
                mask = self._mask()
                newbyte = chr((ord(a) & mask) ^ (ord(b) & ~mask))
                hd = hamming.bitwise_hd(a, newbyte)
                swapped.append(newbyte)
            else:
                swapped.append(a)
        return swapped, hd
