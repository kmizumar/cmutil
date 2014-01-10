#!/usr/bin/env python

__author__ = 'Kiyoshi Mizumaru'
__email__ = 'maru@cloudera.com'

import argparse
import yaml
import sys
from cm_api.api_client import ApiResource

CM_ACCESS = 'cm_access.yaml'

parser = argparse.ArgumentParser(description='Cloudera Manager Dump')
parser.add_argument('-c', '--conf', default=CM_ACCESS,
                    help='Cloudera Manager access information (yaml)')
args = parser.parse_args()
cm_access = None
try:
    f = open(args.conf, 'r')
except IOError as (errno, strerror):
    print "IOerror: [Errno {0}] {1}: '{2}'".format(errno, strerror, args.conf)
    sys.exit(-1)
else:
    cm_access = yaml.load(f)
    f.close()

cm_host = cm_access['cm_host']
cm_port = cm_access['cm_port']
username = cm_access['username']
password = cm_access['password']

api = ApiResource(cm_host, cm_port, username, password)

cdh4 = None

for c in api.get_all_clusters():
    print c.name
    if c.version == 'CDH4':
        cdh4 = c

for s in cdh4.get_all_services():
    print s
    if s.type == 'HDFS':
        hdfs = s

deployment = api.get('/cm/deployment')
mgr = api.get_cloudera_manager()
print mgr.__class__