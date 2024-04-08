#!/usr/bin/python -B
#########################################################################
#   Copyright 2023 VMware, Inc.  All rights reserved. VMware Confidential
#########################################################################
# NOTE: on linux/photon machines execute this file directly
# ----- on windows distribution execute with ""%VMWARE_PYTHON_BIN%" -B%" prefix
from argparse import ArgumentParser
from contextlib import closing
from datetime import datetime, timedelta, tzinfo
try:
   inFnc = raw_input
except:
   inFnc = input
from json import load, dump
from logging import DEBUG, Formatter, Logger, StreamHandler
from os import chmod, environ
from os.path import exists, join
from stat import S_IREAD, S_IWRITE, S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH
from socket import create_connection
from ssl import CERT_NONE, create_default_context, DER_cert_to_PEM_cert, Purpose
from sys import platform, stdout
try:
   from urllib.parse import urlparse
except:
   from urlparse import urlparse

_IS_WINDOWS = platform.lower().startswith('win')

_VMWARE_CFG_ENV = 'VMWARE_CFG_DIR'

_TRUST_FILE = (
   join(environ.get(_VMWARE_CFG_ENV), 'vmware-eam', 'depot-trust.json')
   if _IS_WINDOWS else
   '/etc/vmware-eam/depot-trust.json'
)

_INSTALL_TEXT = (
   'pins an URL\'s leaf certificate in ESX Agent Manager trust store'
)
_UNINSTALL_TEXT = (
   'unpins any known certificate for an URL from ESX Agent Manager\'s' +
   ' trust store'
)
_DISABLE_TEXT = (
   'allows, ESX Agent Manager, access to an URL without establishing' +
   ' trust'
)
_ENABLE_TEXT = (
   'removes permission to access an URL without establishing trust' +
   ' from ESX Agent Manager'
)
_CLEAR_TEXT = 'clears configured ESX Agent Manager trust store'

_DISABLED_MARKER = 'AnyCertificate'

_CANT_MOD_TEXT = 'Unable to read or modify ESX Agent Manager trust at %s'

_LOG_FORMAT = '%(asctime)s %(message)s'
_DATE_FORMAT = '%Y-%m-%d %H:%M:%S %z'

_TRUST_PERMISSIONS = (
   S_IREAD | S_IWRITE | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
)

# In seconds
_CERT_GET_TIMEOUT = 10


def main(args):
   return args.operationFnc(_createTimeZoneLogger(), args)


def _installCert(log, args):
   rc = 0
   url = args.url
   if _needsTrust(url):
      try:
         parts = urlparse(url)
      except:
         log.warning('Couldn\'t parse the provided URL %s', url, exc_info=True)
         rc = 1

      if rc == 0:
         context = create_default_context(purpose=Purpose.SERVER_AUTH)
         # NOTE: Disable hostname verification to be able to access
         # ----- misnamed certificates.
         context.check_hostname = False
         # NOTE: Disable certificate verification to be able to access
         # ----- any kind of certificate on the server.
         context.verify_mode = CERT_NONE

         pem_certificate = None
         try:
            with closing(
               create_connection(
                  (parts.hostname, 443 if parts.port is None else parts.port),
                  timeout=_CERT_GET_TIMEOUT
               )
            ) as sock:
               with closing(
                  context.wrap_socket(
                     sock,
                     server_hostname=parts.hostname,
                     do_handshake_on_connect=True
                  )
               ) as ssock:
                  certificate_binary = ssock.getpeercert(binary_form=True)
                  x509Cert = DER_cert_to_PEM_cert(certificate_binary)
         except:
            self._log.warning(
               'Unable to obtain the certificate from {}'.format(url),
               exc_info=True
            )
            rc = 1

      if rc == 0 and not args.y:
         log.info(
            'PEM encoding of certificate behind URL "%s":\n%s',
            url,
            x509Cert
         )
         answer = inFnc(
            'Do you want associate(pin) this certificate to this URL as trust'
            '(enter "y" to confirm): '
         )
         if not answer.lower() == 'y':
            log.info('User did not agree, stopping the operation')
            rc = 1

      if rc == 0:
         try:
            trust = _readTrust(log, args)
            trust = {} if trust is None else trust
            trust[url] = x509Cert
            _storeTrust(log, args, trust)
         except:
            log.warning(_CANT_MOD_TEXT, args.trust_file, exc_info=True)
            rc = 1
   else:
      log.info(
         'URL "%s" doesn\'t require trust to access. Ignoring command',
         args.url
      )
   return rc;


def _uninstallCert(log, args):
   rc = 0
   url = args.url
   try:
      trust = _readTrust(log, args)
      trust = {} if trust is None else trust
      if url in trust and not trust[url] == _DISABLED_MARKER:
         log.info('Removing certificate pinning for URL %s trust', url)
         del trust[url]
         _storeTrust(log, args, trust)
      else:
         log.info(
            (
               'URL "%s" doesn\'t have a pinned trust certificate.'
               ' Ignoring command'
            ),
            url
         )
   except:
      log.warning(_CANT_MOD_TEXT, args.trust_file, exc_info=True)
      rc = 1
   return rc


def _disableTrust(log, args):
   rc = 0
   url = args.url
   if _needsTrust(url):
      try:
         trust = _readTrust(log, args)
         trust = {} if trust is None else trust
         if url in trust and trust[url] == _DISABLED_MARKER:
            log.info(
               'URL "%s" already with disabled trust. Ignoring command',
               url
            )
         else:
            log.info('Allowing URL "%s" access without establishing trust', url)
            trust[url] = _DISABLED_MARKER
            _storeTrust(log, args, trust)
      except:
         log.warning(_CANT_MOD_TEXT, args.trust_file, exc_info=True)
         rc = 1
   else:
      log.info(
         'URL "%s" doesn\'t require trust to access. Ignoring command',
         url
      )
   return rc;


def _enableTrust(log, args):
   rc = 0
   url = args.url
   try:
      trust = _readTrust(log, args)
      trust = {} if trust is None else trust
      if url in trust and trust[url] == _DISABLED_MARKER:
         log.info(
            'Removing permission to access URL %s without establishing trust',
            url
         )
         del trust[url]
         _storeTrust(log, args, trust)
      else:
         log.info('URL "%s" is not with disabled trust. Ignoring command', url)
   except:
      log.warning(_CANT_MOD_TEXT, args.trust_file, exc_info=True)
      rc = 1
   return rc


def _clearTrust(log, args):
   rc = 0
   if exists(args.trust_file):
      log.info('Clearing ESX Agent Manager trust.')
      try:
         _storeTrust(log, args, {})
      except:
         log.warning(_CANT_MOD_TEXT, args.trust_file, exc_info=True)
         rc = 1
   else:
      log.info(
         'ESX Agent Manager trust not found at %s. Ignoring command',
         args.trust_file
      )
   return rc;


def arguments():
   parser = ArgumentParser(
      prog='eam-utility',
      description='Modifies ESX Agent Manager configuration/state'
   )
   subParsers = parser.add_subparsers(
      title='operations',
      dest='operation',
      help='operations to modify EAM\'s configuration/state'
   )
   # NOTE: not in the above method to allow work with python 2
   subParsers.required=True

   addCertParser = subParsers.add_parser(
      'install-cert',
      description=_INSTALL_TEXT,
      help=_INSTALL_TEXT
   )
   addCertParser.add_argument(
      'url',
      help=(
         'URL to have its certificate pinned to ESX Agent Manager\'s' +
         ' trust store'
      )
   )
   _addTrustFileArgument(addCertParser)
   addCertParser.add_argument(
      '-y',
      action='store_true',
      help='accept any certificate behind the URL without confirmation'
   )
   addCertParser.set_defaults(operationFnc=_installCert)

   removeCertParser = subParsers.add_parser(
      'uninstall-cert',
      description=_UNINSTALL_TEXT,
      help=_UNINSTALL_TEXT
   )
   removeCertParser.add_argument(
      'url',
      help=(
         'URL to have its certificate unpinned from ESX Agent Manager\'s' +
         ' trust store'
      )
   )
   _addTrustFileArgument(removeCertParser)
   removeCertParser.set_defaults(operationFnc=_uninstallCert)

   disableTrustParser = subParsers.add_parser(
      'disable-trust',
      description=_DISABLE_TEXT,
      help=_DISABLE_TEXT
   )
   disableTrustParser.add_argument(
      'url',
      help=(
         'URL to be accessible by ESX Agent Manager without establishing trust'
      )
   )
   _addTrustFileArgument(disableTrustParser)
   disableTrustParser.set_defaults(operationFnc=_disableTrust)

   enableTrustParser = subParsers.add_parser(
      'enable-trust',
      description=_ENABLE_TEXT,
      help=_ENABLE_TEXT
   )
   enableTrustParser.add_argument(
      'url',
      help=(
         'URL to no-longer be accessible by ESX Agent Manger without' +
         ' establishing trust'
      )
   )
   _addTrustFileArgument(enableTrustParser)
   enableTrustParser.set_defaults(operationFnc=_enableTrust)

   clearTrustParser = subParsers.add_parser(
      'clear-trust',
      description=_CLEAR_TEXT,
      help=_CLEAR_TEXT
   )
   _addTrustFileArgument(clearTrustParser)
   clearTrustParser.set_defaults(operationFnc=_clearTrust)

   return parser.parse_args()


def _addTrustFileArgument(parser):
   parser.add_argument(
      '--trust-file',
      metavar='file',
      default=_TRUST_FILE,
      help=(
         'Path to file containing ESX Agent Manager\'s trust store' +
         ' (default: %(default)s)'
      )
   )


def _needsTrust(url):
   return url is not None and url.lower().startswith('https://')


def _readTrust(log, args):
   if exists(args.trust_file):
      log.info('Loading ESX Agent Manager trust from %s', args.trust_file)
      with open(args.trust_file, 'r') as fin:
         trust = load(fin)
   else:
      log.info(
         'ESX Agent Manager trust doesn\'t exist at %s, using empty trust',
         args.trust_file
      )
      trust = None
   return trust


def _storeTrust(log, args, trust):
   log.info('Storing ESX Agent Manager trust to %s', args.trust_file)
   with open(args.trust_file, 'w') as fout:
      dump(trust, fout, indent=3)
   chmod(args.trust_file, _TRUST_PERMISSIONS)


def _createTimeZoneLogger():
   logger = Logger('main', DEBUG)
   handler = StreamHandler(stdout)
   handler.setFormatter(_TimeZonedFormatter(_LOG_FORMAT, _DATE_FORMAT))
   logger.addHandler(handler)
   return logger


class _TimeZonedFormatter(Formatter):

   def formatTime(self, record, datefmt=None):
      timeZone = _TimeZone(
         int((datetime.now() - datetime.utcnow()).total_seconds())
      )
      tzTime = datetime.fromtimestamp(record.created, timeZone)
      return tzTime.strftime(datefmt if datefmt is not None else _DATE_FORMAT)


class _TimeZone(tzinfo):

   def __init__(self, seconds):
      # the timezone doesn't work with fractional minutes
      fraction = seconds % 60
      secondsFixed = (
         (seconds - fraction) if fraction < 30
         else (seconds + 60 - fraction)
      )
      self._td = timedelta(seconds=secondsFixed)

   def utcoffset(self, dt):
      return self._td

   def tzname(self, dt):
      return 'Custom'

   def dst(self, dt):
      return timedelta(0)


if __name__ == '__main__':
   exit(main(arguments()))
