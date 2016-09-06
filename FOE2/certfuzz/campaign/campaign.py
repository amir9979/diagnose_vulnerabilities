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
Created on Feb 9, 2012

@organization: cert.org
'''

import logging
import os
import sys
import shutil
import tempfile
import traceback
import re
import cPickle as pickle
from threading import Timer
import platform
import gc

from . import __version__
from . import import_module_by_name
from . import CampaignBase
from . import CampaignError
from .config.foe_config import Config
from .iteration import Iteration

from ..debuggers import registration
from ..fuzztools import filetools
from ..file_handlers.seedfile_set import SeedfileSet
from ..fuzzers import FuzzerExhaustedError
from ..scoring.scorable_set import EmptySetError
from ..runners import RunnerArchitectureError
from ..runners.killableprocess import Popen
from certfuzz.runners import RunnerPlatformVersionError
from ..fuzztools.object_caching import dump_obj_to_file

logger = logging.getLogger(__name__)

packages = {'fuzzers': 'certfuzz.fuzzers',
            'runners': 'certfuzz.runners',
            'debuggers': 'certfuzz.debuggers',
            }

class Campaign(CampaignBase):
    '''
    Provides a fuzzing campaign object.
    '''
    def __init__(self, config_file, result_dir=None, campaign_cache=None,
                 debug=False):
        '''
        Typically one would invoke a campaign as follows:

        with Campaign(params) as campaign:
            campaign.go()

        This will ensure that the runtime context is established properly, and
        that any cleanup activities can be completed if exceptions occur.

        @param config_file: path to a config file
        @param result_dir: path to a result directory
        (will be created if necessary)
        @param campaign_cache: path to a cached json object to rebuild an
        existing campaign
        @param debug: boolean indicating whether we are in debug mode
        '''
        logger.debug('initialize %s', self.__class__.__name__)
        self.config_file = config_file
        self.cached_state_file = campaign_cache
        self.debug = debug
        self._version = __version__
        self.gui_app = False

        cfgobj = Config(self.config_file)
        self.config = cfgobj.config
        self.configdate = cfgobj.configdate

        self.id = self.config['campaign']['id']
        self.use_buttonclicker = self.config['campaign'].get('use_buttonclicker')
        if not self.use_buttonclicker:
            self.use_buttonclicker = False

        self.current_seed = self.config['runoptions'].get('first_iteration')
        if not self.current_seed:
            # default to zero
            self.current_seed = 0
        # if stop_seed is zero or None, we'll keep going forever
        # see self._keep_going()
        self.stop_seed = self.config['runoptions'].get('last_iteration')

        self.seed_interval = self.config['runoptions'].get('seed_interval')
        if not self.seed_interval:
            self.seed_interval = 1

        if result_dir:
            self.outdir_base = os.path.abspath(result_dir)
        else:
            self.outdir_base = os.path.abspath(self.config['directories']['results_dir'])

        self.outdir = os.path.join(self.outdir_base, self.id)
        logger.debug('outdir=%s', self.outdir)
        self.sf_set_out = os.path.join(self.outdir, 'seedfiles')

        self.work_dir_base = os.path.abspath(self.config['directories']['working_dir'])

        if not self.cached_state_file:
            cachefile = 'campaign_%s.pkl' % re.sub('\W', '_', self.id)
            self.cached_state_file = os.path.join(self.work_dir_base, cachefile)

        self.seed_dir_in = self.config['directories']['seedfile_dir']

        self.keep_duplicates = self.config['runoptions']['keep_all_duplicates']
        self.keep_heisenbugs = self.config['campaign']['keep_heisenbugs']
        self.should_keep_u_faddr = self.config['runoptions']['keep_unique_faddr']

        # TODO: consider making this configurable
        self.status_interval = 100

        self.prog = self.config['target']['program']
        self.cmd_template = self.config['target']['cmdline_template']
        self.crashes_seen = set()

        self.runner_module_name = None
        self.runner_module = None
        self.runner = None

        self.seedfile_set = None

        self.fuzzer_module_name = '%s.%s' % (packages['fuzzers'], self.config['fuzzer']['fuzzer'])
        if self.config['runner']['runner']:
            self.runner_module_name = '%s.%s' % (packages['runners'], self.config['runner']['runner'])
        self.debugger_module_name = '%s.%s' % (packages['debuggers'], self.config['debugger']['debugger'])

    def __enter__(self):
        '''
        Creates a runtime context for the campaign.
        '''
        self._read_state()
        self._check_prog()
        self._setup_workdir()
        self._set_fuzzer()
        self._set_runner()
        self._set_debugger()
        self._setup_output()
        self._create_seedfile_set()
        # buttonclicker is os-specific, moved to subclass
#        self._start_buttonclicker()
        return self

    def __exit__(self, etype, value, mytraceback):
        '''
        Handles known exceptions gracefully, attempts to clean up temp files
        before exiting.
        '''
        handled = False
#        self._stop_buttonclicker()
        if etype is KeyboardInterrupt:
            logger.warning('Keyboard interrupt - exiting')
            handled = True
        elif etype is RunnerArchitectureError:
            logger.error('Unsupported architecture: %s', value)
            logger.error('Set "verify_architecture=false" in the runner \
                section of your config to override this check')
            handled = True
        elif etype is RunnerPlatformVersionError:
            logger.error('Unsupported platform: %s', value)
            handled = True
        elif etype:
            logger.debug('Unhandled exception:')
            logger.debug('  type: %s', etype)
            logger.debug('  value: %s', value)
            for l in traceback.format_exception(etype, value, mytraceback):
                logger.debug(l.rstrip())
        if self.debug and etype and not handled:
            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            self._cleanup_workdir()

        return handled

    def _check_prog(self):
        if not os.path.exists(self.prog):
            msg = 'Cannot find program "%s" (resolves to "%s")' % (self.prog, os.path.abspath(self.prog))
            raise CampaignError(msg)

    def _set_fuzzer(self):
        self.fuzzer_module = import_module_by_name(self.fuzzer_module_name, logger)
        self.fuzzer = self.fuzzer_module._fuzzer_class

    def _set_runner(self):
        if self.runner_module_name:
            self.runner_module = import_module_by_name(self.runner_module_name, logger)
            self.runner = self.runner_module._runner_class

    def _set_debugger(self):
        # this will import the module which registers the debugger
        self.debugger_module = import_module_by_name(self.debugger_module_name, logger)
        # confirm that the registered debugger is compatible
        registration.verify_supported_platform()
        # now we have some class
        self.dbg_class = registration.debug_class

    def _write_version(self):
        CampaignBase._write_version(self)

    def _setup_output(self):
        # construct run output directory
        filetools.make_directories(self.outdir)
        # copy config to run output dir
        filetools.copy_file(self.config_file, self.outdir)
        self._write_version()

    def _setup_workdir(self):
        # make_directories silently skips existing dirs, so it's okay to call
        # it even if work_dir_base already exists
        filetools.make_directories(self.work_dir_base)
        # now we're sure work_dir_base exists, so it's safe to create temp dirs
        self.working_dir = tempfile.mkdtemp(prefix='campaign_', dir=self.work_dir_base)
        self.seed_dir_local = os.path.join(self.working_dir, 'seedfiles')

    def _cleanup_workdir(self):
        try:
            shutil.rmtree(self.working_dir)
        except:
            pass

        if os.path.exists(self.working_dir):
            logger.warning("Unable to remove campaign working dir: %s", self.working_dir)
        else:
            logger.debug('Removed campaign working dir: %s', self.working_dir)

    def _create_seedfile_set(self):
        if self.seedfile_set is None:
            with SeedfileSet(self.id, self.seed_dir_in, self.seed_dir_local,
                             self.sf_set_out) as sfset:
                self.seedfile_set = sfset

    def __setstate__(self, state):
        # turn the list into a set
        state['crashes_seen'] = set(state['crashes_seen'])

        # reconstitute the seedfile set
        with SeedfileSet(state['id'], state['seed_dir_in'], state['seed_dir_local'],
                         state['sf_set_out']) as sfset:
            new_sfset = sfset

        new_sfset.__setstate__(state['seedfile_set'])
        state['seedfile_set'] = new_sfset

        # update yourself
        self.__dict__.update(state)

    def _read_state(self, cache_file=None):
        if not cache_file:
            cache_file = self.cached_state_file

        if not os.path.exists(cache_file):
            logger.info('No cached campaign found, using new campaign')
            return

        try:
            with open(cache_file, 'rb') as fp:
                campaign = pickle.load(fp)
        except Exception, e:
            logger.warning('Unable to read %s, will use new campaign instead: %s', cache_file, e)
            return

        if campaign:
            try:
                if self.configdate != campaign.__dict__['configdate']:
                    logger.warning('Config file modified. Discarding cached campaign')
                else:
                    self.__dict__.update(campaign.__dict__)
                    logger.info('Reloaded campaign from %s', cache_file)
            except KeyError:
                logger.warning('No config date detected. Discarding cached campaign')
        else:
            logger.warning('Unable to reload campaign from %s, will use new campaign instead', cache_file)

    def __getstate__(self):
        state = self.__dict__.copy()

        state['crashes_seen'] = list(state['crashes_seen'])
        if state['seedfile_set']:
            state['seedfile_set'] = state['seedfile_set'].__getstate__()

        # for attributes that are modules,
        # we can safely delete them as they will be
        # reconstituted when we __enter__ a context
        for key in ['fuzzer_module', 'fuzzer',
                    'runner_module', 'runner',
                    'debugger_module', 'dbg_class'
                    ]:
            if key in state:
                del state[key]
        return state

    def _save_state(self, cachefile=None):
        if not cachefile:
            cachefile = self.cached_state_file
        dump_obj_to_file(cachefile, self)

    def _crash_is_unique(self, crash_id, exploitability='UNKNOWN'):
        '''
        If crash_id represents a new crash, add the crash_id to crashes_seen
        and return True. Otherwise return False.

        @param crash_id: the crash_id to look up
        @param exploitability: not used at this time
        '''
        if not crash_id in self.crashes_seen:
            self.crashes_seen.add(crash_id)
            return True
        return False

    def _keep_going(self):
        if self.stop_seed:
            return self.current_seed < self.stop_seed
        else:
            return True

    def _do_interval(self):
        # choose seedfile
        sf = self.seedfile_set.next_item()

        logger.info('Selected seedfile: %s', sf.basename)
        rng_seed = int(sf.md5, 16)

        if self.current_seed % self.status_interval == 0:
            # cache our current state
            self._save_state()

        # don't overshoot stop_seed
        interval_limit = self.current_seed + self.seed_interval
        if self.stop_seed:
            interval_limit = min(interval_limit, self.stop_seed)

        # start an iteration interval
        # note that range does not include interval_limit
        for seednum in xrange(self.current_seed, interval_limit):
            self._do_iteration(sf, rng_seed, seednum)

        del sf
        # manually collect garbage
        gc.collect()

        self.current_seed = interval_limit

    def _do_iteration(self, sf, rng_seed, seednum):
        iter_args = (sf, rng_seed, seednum, self.config, self.fuzzer,
                     self.runner, self.debugger_module, self.dbg_class,
                     self.keep_heisenbugs, self.keep_duplicates,
                     self.cmd_template, self._crash_is_unique,
                     self.working_dir, self.outdir, self.debug)
        # use a with...as to ensure we always hit
        # the __enter__ and __exit__ methods of the
        # newly created Iteration()
        with Iteration(*iter_args) as iteration:
            try:
                iteration.go(self.seedfile_set)
            except FuzzerExhaustedError:
                # Some fuzzers run out of things to do. They should
                # raise a FuzzerExhaustedError when that happens.
                logger.info('Done with %s, removing from set', sf.basename)
                self.seedfile_set.del_item(sf.md5)
        if not seednum % self.status_interval:
            logger.info('Iteration: %d Crashes found: %d', self.current_seed,
                        len(self.crashes_seen))
            self.seedfile_set.update_csv()
            logger.info('Seedfile Set Status:')
            for k, score, successes, tries, p in self.seedfile_set.status():
                logger.info('%s %0.6f %d %d %0.6f', k, score, successes,
                            tries, p)

    def go(self):
        while self._keep_going():
            try:
                self._do_interval()
            except EmptySetError:
                logger.info('Seedfile set is empty. Nothing more to do.')
                return

class WindowsCampaign(Campaign):
    '''
    Extends Campaign to add windows-specific features like ButtonClicker
    '''
    def __enter__(self):
        if sys.platform == 'win32':
            winver = sys.getwindowsversion().major
            machine = platform.machine()
            hook_incompat = (winver > 5) or (machine == 'AMD64')
            if hook_incompat and self.runner_module_name == 'certfuzz.runners.winrun':
                logger.debug('winrun is not compatible with Windows %s %s. Overriding.', winver, machine)
                self.runner_module_name = None
        self = Campaign.__enter__(self)
        self._start_buttonclicker()
        self._cache_app()
        return self

    def __exit__(self, etype, value, mytraceback):
        self._stop_buttonclicker()
        return Campaign.__exit__(self, etype, value, mytraceback)

    def _cache_app(self):
        logger.debug('Caching application %s and determining if we need to watch the CPU...', self.prog)
        targetdir = os.path.dirname(self.prog)
        # Use overriden Popen that uses a job object to make sure that
        # child processes are killed
        p = Popen(self.prog, cwd=targetdir)
        runtimeout = self.config['runner']['runtimeout']
        logger.debug('...Timer: %f', runtimeout)
        t = Timer(runtimeout, self.kill, args=[p])
        logger.debug('...timer start')
        t.start()
        p.wait()
        logger.debug('...timer stop')
        t.cancel()
        if not self.gui_app:
            logger.debug('This seems to be a CLI application.')
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = str(self.config['debugger']['watchcpu']).lower()
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Disabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = False
        if debugger_watchcpu == 'auto':
            logger.debug('Disabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = False

    def kill(self, p):
        # The app didn't complete within the timeout.  Assume it's a GUI app
        logger.debug('This seems to be a GUI application.')
        self.gui_app = True
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = str(self.config['debugger']['watchcpu']).lower()
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Enabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = True
            logger.debug('kill runner watchcpu: %s', self.config['runner']['watchcpu'])
        if debugger_watchcpu == 'auto':
            logger.debug('Enabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = True
            logger.debug('kill debugger watchcpu: %s', self.config['debugger']['watchcpu'])
        logger.debug('kill %s', p)
        p.kill()

    def _start_buttonclicker(self):
        if self.use_buttonclicker:
            rootpath = os.path.dirname(sys.argv[0])
            buttonclicker = os.path.join(rootpath, 'buttonclicker', 'buttonclicker.exe')
            os.startfile(buttonclicker)  # @UndefinedVariable

    def _stop_buttonclicker(self):
        if self.use_buttonclicker:
            os.system('taskkill /im buttonclicker.exe')
