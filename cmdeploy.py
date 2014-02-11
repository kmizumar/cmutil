#!/usr/bin/env python

__author__ = 'Kiyoshi Mizumaru'
__email__ = 'kiyoshi.mizumaru@gmail.com'

import argparse
import os
import sys
import yaml
from cm_api.api_client import ApiResource

CM_ACCESS = 'cm_access.yaml'

parser = argparse.ArgumentParser(description='Cloudera Manager Deployment Dump')
parser.add_argument('-c', '--conf', default=CM_ACCESS, metavar='yaml',
                    help='cloudera manager access information')
parser.add_argument('input', help='cloudera manager deployment information')
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

if args.input:
    input = args.input
else:
    input = '{0}:{1}.json'.format(cm_host, cm_port)

api = ApiResource(cm_host, cm_port, username, password)

if os.path.exists(input):
    try:
        f = open(input, mode='r')
    except IOError as (errno, strerror):
        print "IOError: [Errno {0}] {1}: '{2}'".format(errno, strerror, input)
        sys.exit(-1)
    else:
        api.put(relpath='/cm/deployment', params={'deleteCurrentDeployment': True},
                data=f.read())
        f.close()
else:
    print "input file does not exist: '{0}'".format(input)
    sys.exit(-1)
