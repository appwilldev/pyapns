import json
import struct
import xmlrpclib
import threading
import httplib
import functools
from sys import hexversion

OPTIONS = {'CONFIGURED': False, 'TIMEOUT': 20}

def configure(opts):
  if not OPTIONS['CONFIGURED']:
    try: # support for django
      import django.conf
      OPTIONS.update(django.conf.settings.PYAPNS_CONFIG)
      OPTIONS['CONFIGURED'] = True
    except:
      pass
    if not OPTIONS['CONFIGURED']:
      try: # support for programatic configuration
        OPTIONS.update(opts)
        OPTIONS['CONFIGURED'] = True
      except:
        pass
    if not OPTIONS['CONFIGURED']:
      try: # pylons support
        import pylons.config
        OPTIONS.update({'HOST': pylons.config.get('pyapns_host')})
        try:
          OPTIONS.update({'TIMEOUT': int(pylons.config.get('pyapns_timeout'))})
        except:
          pass # ignore, an optional value
        OPTIONS['CONFIGURED'] = True
      except:
        pass
    # provision initial app_ids
    if 'INITIAL' in OPTIONS:
      for args in OPTIONS['INITIAL']:
        provision(*args)
  return OPTIONS['CONFIGURED']


class UnknownAppID(Exception): pass
class APNSNotConfigured(Exception): pass

def reprovision_and_retry(func):
  """
  Wraps the `errback` callback of the API functions, automatically trying to
  re-provision if the app ID can not be found during the operation. If that's
  unsuccessful, it will raise the UnknownAppID error.
  """
  @functools.wraps(func)
  def wrapper(*a, **kw):
    errback = kw.get('errback', None)
    if errback is None:
      def errback(e):
        raise e
    def errback_wrapper(e):
      if isinstance(e, UnknownAppID) and 'INITIAL' in OPTIONS:
        try:
          for initial in OPTIONS['INITIAL']:
            provision(*initial) # retry provisioning the initial setup
          func(*a, **kw) # and try the function once more
        except Exception, new_exc:
          errback(new_exc) # throwing the new exception
      else:
        errback(e) # not an instance of UnknownAppID - nothing we can do here
    kw['errback'] = errback_wrapper
    return func(*a, **kw)
  return wrapper

def default_callback(func):
  @functools.wraps(func)
  def wrapper(*a, **kw):
    if 'callback' not in kw:
      kw['callback'] = lambda c: c
    return func(*a, **kw)
  return wrapper

@default_callback
@reprovision_and_retry
def provision(app_id, path_to_cert, environment, timeout=15, async=False,
              callback=None, errback=None):
  args = [app_id, path_to_cert, environment, timeout]
  f_args = ['provision', args, callback, errback]
  if not async:
    return _xmlrpc_thread(*f_args)
  t = threading.Thread(target=_xmlrpc_thread, args=f_args)
  t.daemon = True
  t.start()

@default_callback
@reprovision_and_retry
def notify(app_id, tokens, notifications, async=False, callback=None,
           errback=None):
  args = [app_id, tokens, notifications]
  f_args = ['notify', args, callback, errback]
  if not async:
    return _xmlrpc_thread(*f_args)
  t = threading.Thread(target=_xmlrpc_thread, args=f_args)
  t.daemon = True
  t.start()

@default_callback
@reprovision_and_retry
def feedback(app_id, async=False, callback=None, errback=None):
  args = [app_id]
  f_args = ['feedback', args, callback, errback]
  if not async:
    return _xmlrpc_thread(*f_args)
  t = threading.Thread(target=_xmlrpc_thread, args=f_args)
  t.daemon = True
  t.start()

def _xmlrpc_thread(method, args, callback, errback=None):
  if not configure({}):
    raise APNSNotConfigured('APNS Has not been configured.')
  proxy = ServerProxy(OPTIONS['HOST'], allow_none=True, use_datetime=True,
                      timeout=OPTIONS['TIMEOUT'])
  try:
    parts = method.strip().split('.')
    for part in parts:
      proxy = getattr(proxy, part)
    return callback(proxy(*args))
  except xmlrpclib.Fault, e:
    if e.faultCode == 404:
      e = UnknownAppID()
    if errback is not None:
      errback(e)
    else:
      raise e


## --------------------------------------------------------------
## Thank you Volodymyr Orlenko:
## http://blog.bjola.ca/2007/08/using-timeout-with-xmlrpclib.html
## --------------------------------------------------------------

def ServerProxy(url, *args, **kwargs):
  t = TimeoutTransport()
  t.timeout = kwargs.pop('timeout', 20)
  kwargs['transport'] = t
  return xmlrpclib.ServerProxy(url, *args, **kwargs)

class TimeoutTransport(xmlrpclib.Transport):
  def make_connection(self, host):
    if hexversion < 0x02070000:
        conn = TimeoutHTTP(host)
        conn.set_timeout(self.timeout)
    else:
        conn = TimeoutHTTPConnection(host)
        conn.timeout = self.timeout
    return conn

class TimeoutHTTPConnection(httplib.HTTPConnection):
  def connect(self):
    httplib.HTTPConnection.connect(self)
    self.sock.settimeout(self.timeout)

class TimeoutHTTP(httplib.HTTP):
  _connection_class = TimeoutHTTPConnection

  def set_timeout(self, timeout):
    self._conn.timeout = timeout

#########################################################
# ClientP4
################

import socket

def parse_netint(b):
    return struct.unpack('!I', b)[0]

def pack_netint(i):
    return struct.pack('!I', i)

def write_response(sock, s):
    if isinstance(s, dict):
      s = json.dumps(s)
    if isinstance(s, unicode):
      # Python 2.x defaults to 'ascii' :-(
      s = s.encode('utf-8')
    sock.sendall(pack_netint(len(s)) + s)

def read_response(sock):
  r = recvbytes(sock, 4)
  if not r:
    return

  length = parse_netint(r)
  data = recvbytes(sock, length)
  if data is None:
    return None
  return fromjson(data)

class ClientP4(object):

    def __init__(self, addr):
        sock = self.sock = socket.socket()
        if addr.endswith("/"): addr=addr[:-1]
        if addr.startswith("http://"):
          addr = addr[7:]
          addr = addr.split(":")
          addr = (addr[0], int(addr[1]))
        #endif
        sock.connect(addr)

    def do_cmd(self, cmd, **other):
      d = { 'cmd': cmd }
      d.update(other)
      write_response(self.sock, d)
      # need not response
      # return read_response(self.sock)

CLIENT_P4=None
def get_clientp4():
  global CLIENT_P4
  if not CLIENT_P4:
    CLIENT_P4 = ClientP4(OPTIONS.get("HOST","http://localhost:8000"))
  #endif
  return CLIENT_P4

def provisionp4(app_id, path_to_cert, environment):
  c = get_clientp4()
  c.do_cmd("provision",
           app_id = app_id,
           cert   = path_to_cert,
           env    = environment)

def notifyp4(app_id, tokens, notifications):
  c = get_clientp4()
  c.do_cmd("notify",
           app_id = app_id,
           tokens = tokens,
           notify = notifications)
