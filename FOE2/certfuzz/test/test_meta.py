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
Created on Apr 10, 2012

@organization: cert.org
'''

import unittest
import os
from certfuzz.fuzztools import filetools

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'certfuzz'))
ignorelist = ['obsolete', 'dist']

def find_packages(d):
    dirlist = [os.path.join(d, x) for x in os.listdir(d) if not x in ignorelist]
    dirs = [x for x in dirlist if os.path.isdir(x)]
    pkgs = [x for x in dirs if '__init__.py' in os.listdir(x)]
    subpkgs = []
    for pkg in pkgs:
        subpkgs.extend(find_packages(pkg))

    pkgs.extend(subpkgs)
    return pkgs

def non_tst_packages(d):
    pkglist = []
    for path in find_packages(d):
        if not os.sep + 'test' in path:
            pkglist.append(path)
    return pkglist

def find_all_modules(d):
    ignore_list = list(ignorelist)
    ignore_list.append('test')
    # ignore dirs with obsolete, dist, test in them
    ignore = lambda f: any(['%s%s%s' % (os.sep, x, os.sep) in f for x in ignore_list])
    return [x for x in filetools.all_files(d, "*.py") if not ignore(x)]

def find_modules(d):
    # ignore __init__.py modules
    return [x for x in find_all_modules(d) if not x.endswith('__init__.py')]

class Test(unittest.TestCase):

    def setUp(self):
        self.basedir = basedir

    def tearDown(self):
        pass

    def test_each_package_has_a_test_package(self):
        package_list = find_packages(self.basedir)

        missing_pkgs = []
        non_pkgs = []
        for pkg in non_tst_packages(self.basedir):
            relpath = os.path.relpath(pkg, basedir)
            test_pkg = os.path.join(basedir, 'test', relpath)
            if not os.path.exists(test_pkg):
                missing_pkgs.append(test_pkg)
            if not test_pkg in package_list:
                non_pkgs.append(test_pkg)
        self.assertFalse(missing_pkgs, 'Missing test packages:\n  %s' % '\n  '.join(missing_pkgs))
        self.assertFalse(non_pkgs, 'Not a package:\n  %s' % '\n  '.join(non_pkgs))

    def test_each_module_has_a_test_module(self):
        module_list = find_modules(self.basedir)
        missing_modules = []
        for m in module_list:
            d, b = os.path.split(m)
            test_b = 'test_%s' % b
            relpath = os.path.relpath(d, basedir)
            test_path = os.path.join(basedir, 'test', relpath, test_b)
            if not os.path.exists(test_path):
                missing_modules.append((os.path.relpath(m, basedir), os.path.relpath(test_path, basedir)))
        fail_lines = ['Module %s has no corresponding test module %s' % mm for mm in missing_modules]
        fail_string = '\n  '.join(fail_lines)
        self.assertFalse(missing_modules, fail_string)

    def test_each_nonempty_init_module_has_a_test_module(self):
        module_list = filetools.all_files(self.basedir, '__init__.py')
        nonempty_mods = [x for x in module_list if os.path.getsize(x)]

        missing_mods = []
        for m in nonempty_mods:
            d = os.path.dirname(m)
            if os.sep + 'test' in d:
                continue
            if os.sep + 'dist' + os.sep in d:
                continue

            test_base = os.path.basename(d)
            test_b = 'test_%s_pkg.py' % test_base
            relpath = os.path.relpath(d, basedir)

            test_path = os.path.join(basedir, 'test', relpath, test_b)
            if not os.path.exists(test_path):
                missing_mods.append((os.path.relpath(d, basedir), os.path.relpath(test_path, basedir)))
        fail_lines = ['Package %s has no corresponding test module %s' % mm for mm in missing_mods]
        fail_string = '\n'.join(fail_lines)
        self.assertFalse(missing_mods, fail_string)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
