#!/usr/bin/env python

__author__ = 'Kiyoshi Mizumaru'
__email__ = 'kiyoshi.mizumaru@gmail.com'

import argparse
import json
import os
import sys
import yaml
from cm_api.api_client import ApiResource

CM_ACCESS = 'cm_access.yaml'

parser = argparse.ArgumentParser(description='Cloudera Manager Deployment Dump')
parser.add_argument('-c', '--conf', default=CM_ACCESS, metavar='yaml',
                    help='cloudera manager access information')
parser.add_argument('-o', '--output', default='', metavar='json',
                    help='cloudera manager deployment output')
parser.add_argument('-f', '--force', action='store_true',
                    help='overwrite existing dump file')
args = parser.parse_args()
cm_access = None
try:
    f = open(args.conf, 'r')
except IOError as (errno, strerror):
    print "IOError: [Errno {0}] {1}: '{2}'".format(errno, strerror, args.conf)
    sys.exit(-1)
else:
    cm_access = yaml.load(f)
    f.close()

cm_host = cm_access['cm_host']
cm_port = cm_access['cm_port']
username = cm_access['username']
password = cm_access['password']

if args.output:
    output = args.output
else:
    output = '{0}:{1}.json'.format(cm_host, cm_port)

api = ApiResource(cm_host, cm_port, username, password)

if not os.path.exists(output) or args.force:
    try:
        f = open(output, mode='w')
    except IOError as (errno, strerror):
        print "IOError: [Errno {0}] {1}: '{2}'".format(errno, strerror, output)
        sys.exit(-1)
    else:
        json.dump(api.get('/cm/deployment'), f)
        f.close()
else:
    print "output file already exists: '{0}'".format(output)
    sys.exit(-1)