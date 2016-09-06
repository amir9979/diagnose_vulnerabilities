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
Created on Aug 19, 2011

@organization: cert.org
'''
import sys
import os
import numpy
import hcluster
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class DistanceMatrixError(Exception):
    pass

class DistanceMatrix(object):
    def __init__(self, similarity_dict):
        self.sim = similarity_dict
        self.keys = []
        self.get_keys()

        self.calculate_distance_matrix()

        self.cluster_method = self.get_cluster_method()

        self.Z = self.cluster_method(self.distance_matrix)
        self.node = hcluster.to_tree(self.Z)
        self.print_node(self.node, self.keys)

        self.image_file = None

    def get_keys(self):
        # make sure we have matched sets
        pairs = self.sim.keys()
        p1 = set()
        p2 = set()
        for (x, y) in pairs:
            p1.add(x)
            p2.add(y)

        self.keys = list(p1.union(p2))

    def calculate_distance_matrix(self):
        key_count = len(self.keys)
        # pre-populate an NxN matrix with zeros
        Y = numpy.zeros((key_count, key_count))
        for i in range(key_count):
            Y[i][i] = 0.0  # diagonal
            a = self.keys[i]
            for j in range(i):
                b = self.keys[j]
                # we don't know which order the tuple should
                # be in, so try both
                k1 = (a, b)
                k2 = (b, a)
                if self.sim.get(k1):
                    Y[i][j] = 1.0 - self.sim[k1]
                    Y[j][i] = Y[i][j]  # mirror image
                elif self.sim.get(k2):
                    Y[j][i] = 1.0 - self.sim[k2]
                    Y[i][j] = Y[j][i]  # mirror image
                else:
                    logger.warning('Key not found in either direction: %s', k1)
        logger.debug(Y)
        self.distance_matrix = Y

    def get_cluster_method(self, algorithm='average'):
        # single: the single/min/nearest algorithm. (alias)
        # complete: the complete/max/farthest algorithm. (alias)
        # average: the average/UPGMA algorithm. (alias)
        # weighted: the weighted/WPGMA algorithm. (alias)
        # centroid: the centroid/UPGMC algorithm. (alias)
        # median: the median/WPGMC algorithm. (alias)
        # ward: the Ward/incremental alg
        logger.debug('Alg = %s', algorithm)
        if algorithm == 'average':
            return hcluster.average
        elif algorithm == 'single':
            return hcluster.single
        elif algorithm == 'complete':
            return hcluster.complete
        elif algorithm == 'weighted':
            return hcluster.weighted
        elif algorithm == 'centroid':
            return hcluster.centroid
        elif algorithm == 'median':
            return hcluster.median
        elif algorithm == 'ward':
            return hcluster.ward
        else:
            sys.exit('Alg must be one of (average, single, complete, weighted, centroid, median, ward)')

    def print_node(self, node, labels, depth=0):
        prefix = ' ' * depth
        if node.id < len(labels):
            filepath = labels[node.id]
            p = os.path.dirname(filepath)
            crash_id = os.path.basename(p)
            label = '|- ' + crash_id
        else:
            label = '%d, %f' % (node.id, node.dist)
        print '%s%s' % (prefix, label)
        if node.left:
            self.print_node(node.left, labels, depth + 1)
        if node.right:
            self.print_node(node.right, labels, depth + 1)

    def to_image(self, filename):
        self.image_file = filename
        self.drawdendrogram()

    def drawdendrogram(self):
        try:
            from PIL import Image, ImageDraw
        except ImportError:
            raise DistanceMatrixError('PIL not available')

        # height and width
        h = self.getheight(self.node) * 20
        w = 1900
        depth = self.getdepth(self.node)

        # width is fixed, so scale distances accordingly
        scaling = float(w - 250) / depth

        # Create a new image with a white background
        img = Image.new('RGB', (w, h), (255, 255, 255))
        draw = ImageDraw.Draw(img)

        draw.line((0, h / 2, 10, h / 2), fill=(255, 0, 0))

        # Draw the first node
        self.drawnode(draw, self.node, 10, (h / 2), scaling)
        print "Saving image to %s" % self.image_file
        img.save(self.image_file)

    def getheight(self, clust):
        # Is this an endpoint? Then the height is just 1
        if clust.left == None and clust.right == None: return 1

        # Otherwise the height is the same of the heights of
        # each branch
        return self.getheight(clust.left) + self.getheight(clust.right)

    def getdepth(self, clust):
        # The distance of an endpoint is 0.0
        if clust.left == None and clust.right == None: return 0

        # The distance of a branch is the greater of its two sides
        # plus its own distance
        return max(self.getdepth(clust.left), self.getdepth(clust.right)) + clust.dist

    def is_leaf(self, node):
        if node.left: return False
        if node.right: return False
        return True

    def drawnode(self, draw, clust, x, y, scaling):
        if self.is_leaf(clust):
            # If this is an endpoint, draw the item label
            draw.text((x + 5, y - 7), self._crash_id_from_path(self.keys[clust.id]), (0, 0, 0))
        else:
            h1 = self.getheight(clust.left) * 20
            h2 = self.getheight(clust.right) * 20
            top = y - (h1 + h2) / 2
            bottom = y + (h1 + h2) / 2
            # Line length
            ll = clust.dist * scaling
            # Vertical line from this cluster to children
            draw.line((x, top + h1 / 2, x, bottom - h2 / 2), fill=(255, 0, 0))

            # Horizontal line to left item
            draw.line((x, top + h1 / 2, x + ll, top + h1 / 2), fill=(255, 0, 0))

            # Horizontal line to right item
            draw.line((x, bottom - h2 / 2, x + ll, bottom - h2 / 2), fill=(255, 0, 0))

            # Call the function to draw the left and right nodes
            self.drawnode(draw, clust.left, x + ll, top + h1 / 2, scaling)
            self.drawnode(draw, clust.right, x + ll, bottom - h2 / 2, scaling)

    def _crash_id_from_path(self, path):
        parts = path.split('/')
        # we assume a directory structure of <foo>/crashers/<crash_id>/<bar>
        idx = parts.index('crashers') + 1
        return parts[idx]
