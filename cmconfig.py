#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Module docstring.
"""
__author__ = 'Kiyoshi Mizumaru'
__email__ = 'kiyoshi.mizumaru@gmail.com'

import argparse
import re
import sys
import yaml
from logging import getLogger,StreamHandler,Formatter,DEBUG,INFO
from cm_api.api_client import ApiResource, ApiException, API_AUTH_REALM
from cm_api.http_client import HttpClient
from cm_api import resource

CLIENT_API_VERSION = 10

logger = getLogger(__name__)
formatter = Formatter('%(asctime)s %(levelname)s %(message)s')
handler = StreamHandler()
handler.setLevel(INFO)
handler.setFormatter(formatter)
logger.setLevel(INFO)
logger.addHandler(handler)


class Resource(resource.Resource):
    """
    Quick and dirty hack of cm_api.resource.Resoruce class
    There's no way to get 'api/version' via current version of
    Cloudera Manager RESTful API Python Client
    """
    def __init__(self, client, relpath=""):
        resource.Resource.__init__(self, client, relpath)

    def invoke(self, method, relpath=None, params=None, data=None, headers=None):
        """
        Invoke an API method.
        @return: Raw string
        """
        path = self._join_uri(relpath)
        resp = self._client.execute(method,
                                    path,
                                    params=params,
                                    data=data,
                                    headers=headers)
        try:
            body = resp.read()
        except Exception, ex:
            raise Exception("Command '%s %s' failed: %s" %
                            (method, path, ex))
        return body


class CmApi(object):
    """

    """
    __cm_port = 7180
    __cm_user = 'admin'
    __cm_pass = 'admin'

    mInitialized = False

    def __init__(self, cminfo):
        """
        Create a CmApi instance

        @param cminfo: Cloudera Manager access info (dict), required
          :host: Cloudera Manager Server host
          :port: Cloudera Manager Server port
          :user: Cloudera Manager login name
          :pass: Cloudera Manager login password
          :use_tls: Whether to use TLS (HTTPS)

        @type cminfo: dict
        """
        if isinstance(cminfo, dict):
            if 'host' in cminfo:
                self.mHost = cminfo['host']
            else:
                raise ValueError("there's no default value for Cloudera Manager Server host")
            self.mPort = cminfo['port'] if 'port' in cminfo else self.__cm_port
            self.mUser = cminfo['user'] if 'user' in cminfo else self.__cm_user
            self.mPass = cminfo['pass'] if 'pass' in cminfo else self.__cm_pass
            if 'use_tls' in cminfo:
                self.mHttps = cminfo['use_tls'] is True or cminfo['use_tls'] is 'true'
            else:
                self.mHttps = False
            self.mApi = ApiResource(self.mHost, server_port=self.mPort,
                                    username=self.mUser, password=self.mPass,
                                    use_tls=self.mHttps, version=CLIENT_API_VERSION)

            base_url = "%s://%s:%s/api/version" % \
                       ('https' if self.mHttps else 'http', self.mHost, self.mPort)
            client = HttpClient(base_url, exc_class=ApiException)
            client.set_basic_auth(self.mUser, self.mPass, API_AUTH_REALM)
            client.set_headers({'Content-Type': 'text/application'})
            self.mSupportedApiVersion = Resource(client).get()
            m = re.match(r'^v(\d+)$', self.mSupportedApiVersion)
            self.mInitialized = CLIENT_API_VERSION <= int(m.group(1))
        else:
            raise ValueError("cminfo must be an instance of dict")

    @classmethod
    def create(cls, host, port=__cm_port, user=__cm_user, password=__cm_pass, use_tls=False):
        """
        Create a CmApi instance

        @param host: Cloudera Manager Server host
        @param port: Cloudera Manager Server port
        @param user: Cloudera Manager login name
        @param password: Cloudera Manager login password
        @param use_tls: Whether to use TLS (HTTPS)

        @type host: basestring
        @type port: int
        @type user: basestring
        @type password: basestring
        @type use_tls: bool

        @return: CmApi instance
        """
        return cls({'host': host, 'port': port, 'user': user, 'pass': password, 'use_tls': use_tls})

    def get_all_clusters(self):
        """
        Retrieve a list of all clusters
        @return: A list of ApiCluster objects.
        """
        if self.mInitialized:
            return self.mApi.get_all_clusters(view='full')
        else:
            raise Exception("this CmApi instance isn't properly initialized")

    def is_valid(self):
        """
        Whether this CmApi instance is properly initialized or not.
        @return: bool
        """
        return self.mInitialized

    def get_supported_api_version(self):
        """
        The latest API version Cloudera Manager server supports.
        @return: basestring
        """
        return self.mSupportedApiVersion


def print_cluster_header(cluster):
    """
    Print a Cluster header

    @param cluster: ApiCluster object
    """
    print "Cluster Name: %s" % cluster.displayName
    print '*' * (len(cluster.displayName) + 14)
    print ""


def print_service_header(service):
    """
    Print a Service header

    @param service: ApiService object
    """
    print "%s (%s)" % (service.displayName, service.clusterRef.clusterName)
    print '=' * (len(service.displayName) +
                 len(service.clusterRef.clusterName) + 3)


def print_service_config(service, displayname=False, description=False):
    """
    Print Service config(s)

    @param service: ApiService object
    @param displayname: show ApiConfig's displayName attribute
    @param description: show ApiConfig's description attribute
    """
    svc_config, rt_config = service.get_config(view='full')
    for k,v in svc_config.iteritems():
        d = v.to_json_dict(preserve_ro=True)
        if v.value is not None:
            print "%s = %s" % (v.name, v.value)
        else:
            if 'default' in d:
                print "%s = None (%s)" % (v.name, d['default'])
            else:
                print "%s = None ( )" % v.name
        if k != v.name:
            logger.error("found discrepancy between key and value.name (%s (%s) %s != %s)"
                         % (service.displayName,
                            service.clusterRef.clusterName,
                            k, v.name))
        if displayname or description:
            if displayname and 'displayName' in d:
                print d['displayName']
            if description and 'description' in d:
                print d['description']

    if len(rt_config) is 0:
        for cg in service.get_all_role_config_groups():
            print ""
            print "%s (%s : %s)" % (cg.displayName, cg.serviceRef.clusterName,
                                    cg.serviceRef.serviceName)
            print '-' * (len(cg.displayName) +
                         len(cg.serviceRef.clusterName) +
                         len(cg.serviceRef.serviceName) + 6)
            for k,v in cg.get_config(view='full').iteritems():
                d = v.to_json_dict(preserve_ro=True)
                if v.value is not None:
                    print "%s = %s" % (v.name, v.value)
                else:
                    if 'default' in d:
                        print "%s = None (%s)" % (v.name, d['default'])
                    else:
                        print "%s = None" % v.name
                if k != v.name:
                    logger.error("found discrepancy between key and value.name (%s != %s"
                                 % (k, v.name))
                if displayname or description:
                    if displayname and 'displayName' in d:
                        print d['displayName']
                    if description and 'description' in d:
                        print d['description']
    else:
        #
        # ApiService#get_config method always return empty dictionary as
        # the role type configurations 2016/01/06, kiyoshi.mizumaru@gmail.com
        #
        logger.error("NOT IMPLEMENTED YET")


class ParserNodeBase(object):
    """

    """
    def __init__(self, cmapi, key):
        self.cmapi = cmapi
        self.key = key

    def list_value_handler(self, value):
        logger.debug("handle value in list")

    def dict_value_handler(self, value):
        logger.debug("handle value in dict")

    def other_value_handler(self, value):
        logger.debug("handle value")

    def found_key(self, value):
        logger.debug("key '%s' found " % self.key)
        if isinstance(value, list):
            logger.debug("value is type of list")
            self.list_value_handler(value)
        elif isinstance(value, dict):
            logger.debug("value is type of dict")
            self.dict_value_handler(value)
        else:
            logger.debug("value is type of non-list and non-dict")
            self.other_value_handler(value)

    def no_key_found(self, value):
        logger.debug("key '%s' not found" % self.key)

    def parse(self, json):
        if self.key in json:
            self.found_key(json[self.key])
        else:
            self.no_key_found(json)


class ParserNode_00(ParserNodeBase):
    """

    """
    def __init__(self, cmapi, displayname=False, description=False):
        ParserNodeBase.__init__(self, cmapi, 'configs')
        self.mDisplayName = displayname
        self.mDescription = description

    def no_key_found(self, value):
        ParserNodeBase.no_key_found(self, value)
        for c in self.cmapi.get_all_clusters():
            print_cluster_header(c)
            for s in c.get_all_services(view='full'):
                print_service_header(s)
                print_service_config(s,
                                     displayname=self.mDisplayName,
                                     description=self.mDescription)
                print ""


def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description='Cloudera Service Configuration Dump')
    parser.add_argument('svcinfo', help='target service information')
    parser.add_argument('-n', '--name', action='store_true',
                        help='show displayName of each config')
    parser.add_argument('-d', '--desc', action='store_true',
                        help='show description of each config')
    args = parser.parse_args()
    svcinfo = None

    try:
        f = open(args.svcinfo, 'r')
    except IOError as (errno, strerror):
        logger.error("IOError: [Errno {0}] {1}: '{2}'".format(errno, strerror, args.svcinfo))
        sys.exit(-1)
    else:
        svcinfo = yaml.load(f)
        f.close()

    for cm in svcinfo:
        api = CmApi(cm)
        ParserNode_00(api, args.name, args.desc).parse(cm)


if __name__ == "__main__":
    sys.exit(main())
