from __future__ import with_statement
import _json as json
import struct
import binascii
import datetime
from StringIO import StringIO as _StringIO
from OpenSSL import SSL, crypto
from twisted.internet import reactor, defer
from twisted.internet.protocol import (
  ReconnectingClientFactory, ClientFactory, Protocol, ServerFactory)
from twisted.internet.ssl import ClientContextFactory
from twisted.application import service
from twisted.protocols.basic import LineReceiver
from twisted.python import log
from zope.interface import Interface, implements
from twisted.web import xmlrpc

#defer.setDebugging(True)

APNS_SERVER_SANDBOX_HOSTNAME = "gateway.sandbox.push.apple.com"
APNS_SERVER_HOSTNAME = "gateway.push.apple.com"
APNS_SERVER_PORT = 2195
FEEDBACK_SERVER_SANDBOX_HOSTNAME = "feedback.sandbox.push.apple.com"
FEEDBACK_SERVER_HOSTNAME = "feedback.push.apple.com"
FEEDBACK_SERVER_PORT = 2196

app_ids = {} # {'app_id': APNSService()}

class StringIO(_StringIO):
  """Add context management protocol to StringIO
      ie: http://bugs.python.org/issue1286
  """

  def __enter__(self):
    if self.closed:
      raise ValueError('I/O operation on closed file')
    return self

  def __exit__(self, exc, value, tb):
    self.close()

class IAPNSService(Interface):
    """ Interface for APNS """

    def write(self, notification):
        """ Write the notification to APNS """

    def read(self):
        """ Read from the feedback service """


class APNSClientContextFactory(ClientContextFactory):
  def __init__(self, ssl_cert_file):
    if 'BEGIN CERTIFICATE' not in ssl_cert_file:
      log.msg('APNSClientContextFactory ssl_cert_file=%s' % ssl_cert_file)
    else:
      log.msg('APNSClientContextFactory ssl_cert_file={FROM_STRING}')
    self.ctx = SSL.Context(SSL.SSLv3_METHOD)
    if 'BEGIN CERTIFICATE' in ssl_cert_file:
      cer = crypto.load_certificate(crypto.FILETYPE_PEM, ssl_cert_file)
      pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, ssl_cert_file)
      self.ctx.use_certificate(cer)
      self.ctx.use_privatekey(pkey)
    else:
      self.ctx.use_certificate_file(ssl_cert_file)
      self.ctx.use_privatekey_file(ssl_cert_file)

  def getContext(self):
    return self.ctx


class APNSProtocol(Protocol):

  def __init__(self, appname="APP-UNSET"):
    #Protocol.__init__(self)
    self.appname = appname

  def connectionMade(self):
    log.msg('APNSProtocol connectionMade app=%s' % self.appname)
    self.factory.addClient(self)

  def sendMessage(self, msg):
    # log.msg('APNSProtocol sendMessage app=%s msg=%s' % (self.appname, binascii.hexlify(msg)))
    # log.msg('APNSProtocol sendMessage app=%s' % self.appname)
    return self.transport.write(msg)

  def connectionLost(self, reason):
    log.msg('APNSProtocol connectionLost app=%s' % self.appname)
    self.factory.removeClient(self)


class APNSFeedbackHandler(LineReceiver):
  MAX_LENGTH = 1024*1024

  def connectionMade(self):
    log.msg('feedbackHandler connectionMade')

  def rawDataReceived(self, data):
    #log.msg('feedbackHandler rawDataReceived %s' % binascii.hexlify(data))
    log.msg('feedbackHandler rawDataReceived %s bytes' % len(data))
    self.io.write(data)

  def lineReceived(self, data):
    #log.msg('feedbackHandler lineReceived %s' % binascii.hexlify(data))
    log.msg('feedbackHandler lineReceived %s bytes' % len(data))
    self.io.write(data)

  def connectionLost(self, reason):
    log.msg('feedbackHandler connectionLost %s' % reason)
    fbs = decode_feedback(self.io.getvalue())
    self.io.close()
    s = "\n".join(map(lambda x: "fail-token:%s" % x[1], fbs))
    log.msg('FEEDBACK: \n%s\n' % s)
    #self.deferred.callback(self.io.getvalue())



class APNSFeedbackClientFactory(ClientFactory):
  protocol = APNSFeedbackHandler

  def __init__(self, appname="APP-UNSET"):
    self.appname = appname
    self.deferred = defer.Deferred()

  def buildProtocol(self, addr):
    p = self.protocol()
    p.factory = self
    p.deferred = self.deferred
    p.io = StringIO()
    p.setRawMode()
    return p

  def startedConnecting(self, connector):
    log.msg('APNSFeedbackClientFactory startedConnecting app=%s' % self.appname)

  def clientConnectionLost(self, connector, reason):
    log.msg('APNSFeedbackClientFactory clientConnectionLost app=%s, reason=%s' % (self.appname, reason))
    ClientFactory.clientConnectionLost(self, connector, reason)

  def clientConnectionFailed(self, connector, reason):
    log.msg('APNSFeedbackClientFactory clientConnectionFailed app=%s, reason=%s' % (self.appname, reason))
    ClientFactory.clientConnectionLost(self, connector, reason)


class APNSClientFactory(ReconnectingClientFactory):
  protocol = APNSProtocol

  def __init__(self, appname="APP-UNSET"):
    self.clientProtocol = None
    self.deferred = defer.Deferred()
    self.deferred.addErrback(log_errback('APNSClientFactory __init__'))
    self.appname = appname

  def addClient(self, p):
    self.clientProtocol = p
    self.deferred.callback(p)

  def removeClient(self, p):
    self.clientProtocol = None
    self.deferred = defer.Deferred()
    self.deferred.addErrback(log_errback('APNSClientFactory removeClient'))

  def startedConnecting(self, connector):
    log.msg('APNSClientFactory startedConnecting app=%s' % self.appname)

  def buildProtocol(self, addr):
    self.resetDelay()
    p = self.protocol(self.appname)
    p.factory = self
    return p

  def clientConnectionLost(self, connector, reason):
    log.msg('APNSClientFactory clientConnectionLost app=%s, reason=%s' % (self.appname, reason))
    ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

  def clientConnectionFailed(self, connector, reason):
    log.msg('APNSClientFactory clientConnectionFailed app=%s, reason=%s' % (self.appname, reason))
    ReconnectingClientFactory.clientConnectionLost(self, connector, reason)


class APNSService(service.Service):
  """ A Service that sends notifications and receives
  feedback from the Apple Push Notification Service
  """

  implements(IAPNSService)
  clientProtocolFactory = APNSClientFactory
  feedbackProtocolFactory = APNSFeedbackClientFactory

  def __init__(self, cert_path, environment, appname="APP-UNSET", timeout=60):
    log.msg('APNSService __init__')
    self.factory = None
    self.environment = environment
    self.cert_path = cert_path
    self.raw_mode = False
    self.appname = appname
    self.timeout = timeout

    log.msg('APNSService write (connecting)')
    server, port = ((APNS_SERVER_SANDBOX_HOSTNAME
                    if self.environment == 'sandbox'
                    else APNS_SERVER_HOSTNAME), APNS_SERVER_PORT)


    self.factory = self.clientProtocolFactory(appname=self.appname)
    context = self.getContextFactory()
    reactor.connectSSL(server, port, self.factory, context)

  def is_valid(self):
    if self.factory.clientProtocol:
      return True
    return False

  def getContextFactory(self):
    return APNSClientContextFactory(self.cert_path)

  def write(self, notifications):
    "Connect to the APNS service and send notifications"
    # if not self.factory:
    #   log.msg('APNSService write (connecting)')
    #   server, port = ((APNS_SERVER_SANDBOX_HOSTNAME
    #                   if self.environment == 'sandbox'
    #                   else APNS_SERVER_HOSTNAME), APNS_SERVER_PORT)
    #
    #   self.factory = self.clientProtocolFactory(appname=self.appname)
    #   context = self.getContextFactory()
    #   reactor.connectSSL(server, port, self.factory, context)

    client = self.factory.clientProtocol
    if client:
      return client.sendMessage(notifications)
    else:
      d = self.factory.deferred
      timeout = reactor.callLater(self.timeout,
        lambda: d.called or d.errback(
          Exception('Notification timed out after %i seconds' % self.timeout)))
      def cancel_timeout(r):
        try: timeout.cancel()
        except: pass
        return r
      d.addCallback(lambda p: p.sendMessage(notifications))
      d.addErrback(log_errback('apns-service-write'))
      d.addBoth(cancel_timeout)
      return d

  def read(self):
    "Connect to the feedback service and read all data."
    log.msg('APNSService read (connecting)')
    try:
      server, port = ((FEEDBACK_SERVER_SANDBOX_HOSTNAME
                      if self.environment == 'sandbox'
                      else FEEDBACK_SERVER_HOSTNAME), FEEDBACK_SERVER_PORT)
      factory = self.feedbackProtocolFactory(self.appname)
      context = self.getContextFactory()
      reactor.connectSSL(server, port, factory, context)
      factory.deferred.addErrback(log_errback('apns-feedback-read'))

      timeout = reactor.callLater(self.timeout,
        lambda: factory.deferred.called or factory.deferred.errback(
          Exception('Feedbcak fetch timed out after %i seconds' % self.timeout)))
      def cancel_timeout(r):
        try: timeout.cancel()
        except: pass
        return r

      factory.deferred.addBoth(cancel_timeout)
    except Exception, e:
      log.err('APNService feedback error initializing: %s' % str(e))
      raise
    return factory.deferred


class APNSServer(xmlrpc.XMLRPC):
  def __init__(self):
    self.app_ids = app_ids
    self.use_date_time = True
    self.useDateTime = True
    xmlrpc.XMLRPC.__init__(self, allowNone=True)

  def apns_service(self, app_id):
    if app_id not in app_ids:
      raise xmlrpc.Fault(404, 'The app_id specified has not been provisioned.')
    services = self.app_ids[app_id]
    ret = services[-1]
    if len(services) > 1:
      tmp = services.pop()
      services.insert(0, tmp)
    #endif
    return ret

  def xmlrpc_provision(self, app_id, path_to_cert_or_cert, environment, timeout=15):
    """ Starts an APNSService for the this app_id and keeps it running

      Arguments:
          app_id                 the app_id to provision for APNS
          path_to_cert_or_cert   absolute path to the APNS SSL cert or a
                                 string containing the .pem file
          environment            either 'sandbox' or 'production'
          timeout                seconds to timeout connection attempts
                                 to the APNS server
      Returns:
          None
    """

    if environment not in ('sandbox', 'production'):
      raise xmlrpc.Fault(401, 'Invalid environment provided `%s`. Valid '
                              'environments are `sandbox` and `production`' % (
                              environment,))
    if not app_id in self.app_ids:
      # log.msg('provisioning ' + app_id + ' environment ' + environment)
      self.app_ids[app_id] = []
      self.app_ids[app_id].append(APNSService(path_to_cert_or_cert, environment, app_id, timeout))
      need_multi = app_id.find("FreeCN_production")>=0 #TODO
      if(need_multi):
        for _ in xrange(90):
          ns = APNSService(path_to_cert_or_cert, environment, app_id, timeout)
          self.app_ids[app_id].append(ns)

  def xmlrpc_notify(self, app_id, token_or_token_list, aps_dict_or_list):
    """ Sends push notifications to the Apple APNS server. Multiple
    notifications can be sent by sending pairing the token/notification
    arguments in lists [token1, token2], [notification1, notification2].

      Arguments:
          app_id                provisioned app_id to send to
          token_or_token_list   token to send the notification or a list of tokens
          aps_dict_or_list      notification dicts or a list of notifications
      Returns:
          None
    """
    d = self.apns_service(app_id).write(
      encode_notifications(
        [t.replace(' ', '') for t in token_or_token_list]
          if (type(token_or_token_list) is list)
          else token_or_token_list.replace(' ', ''),
        aps_dict_or_list))
    if d:
      def _finish_err(r):
        # so far, the only error that could really become of this
        # request is a timeout, since APNS simply terminates connectons
        # that are made unsuccessfully, which twisted will try endlessly
        # to reconnect to, we timeout and notifify the client
        raise xmlrpc.Fault(500, 'Connection to the APNS server could not be made.')
      return d.addCallbacks(lambda r: None, _finish_err)

  def xmlrpc_feedback(self, app_id):
    """ Queries the Apple APNS feedback server for inactive app tokens. Returns
    a list of tuples as (datetime_went_dark, token_str).

      Arguments:
          app_id   the app_id to query
      Returns:
          Feedback tuples like (datetime_expired, token_str)
    """

    return self.apns_service(app_id).read().addCallback(
      lambda r: decode_feedback(r))


def encode_notifications(tokens, notifications):
  """ Returns the encoded bytes of tokens and notifications

        tokens          a list of tokens or a string of only one token
        notifications   a list of notifications or a dictionary of only one
  """

  fmt = "!BH32sH%ds"
  structify = lambda t, p: struct.pack(fmt % len(p), 0, 32, t, len(p), p)
  binaryify = lambda t: t.decode('hex')
  if type(notifications) is dict and type(tokens) in (str, unicode):
    tokens, notifications = ([tokens], [notifications])
  if type(notifications) is list and type(tokens) is list:
    return ''.join(map(lambda y: structify(*y), ((binaryify(t), json.dumps(p, separators=(',',':'), ensure_ascii=False).encode('utf-8'))
                                    for t, p in zip(tokens, notifications))))

def decode_feedback(binary_tuples):
  """ Returns a list of tuples in (datetime, token_str) format

        binary_tuples   the binary-encoded feedback tuples
  """

  fmt = '!lh32s'
  size = struct.calcsize(fmt)
  with StringIO(binary_tuples) as f:
    return [(datetime.datetime.fromtimestamp(ts), binascii.hexlify(tok))
            for ts, toklen, tok in (struct.unpack(fmt, tup)
                              for tup in iter(lambda: f.read(size), ''))]

def log_errback(name):
  def _log_errback(err, *args):
    log.err('errback in %s : %s' % (name, str(err)))
    return err
  return _log_errback

#####################
from twisted.internet import protocol, reactor

def parse_netint(b):
    return struct.unpack('!I', b)[0]

def pack_netint(i):
    return struct.pack('!I', i)

class P4Server(protocol.Protocol):

  def __init__(self):
    self.data = ''
    self.app_apns_services = app_ids
    self.sent_count = 0

  def apns_service(self, app_id):
    if app_id not in app_ids:
      return None

    services = self.app_apns_services[app_id]
    ret = services.pop()

    if ret.is_valid():
      services.insert(0, ret)
    else:
        return None
    #endif
    return ret

  def provision(self, app_name, path_to_cert_or_cert, environment):
    if environment not in ('sandbox', 'production', 'inhouse'):
      return None # TODO log

    if app_name[-11:] == '_production':
      apns_service_count = 100
    else:
      apns_service_count = 5

    if not app_name in self.app_apns_services:
      # log.msg('provisioning ' + app_id + ' environment ' + environment)
      self.app_apns_services[app_name] = []
      for i in xrange(apns_service_count):
        log.msg('Fisrt Add %dth APNSService for %s ' % (i, app_name))
        ns = APNSService(path_to_cert_or_cert, environment, app_name, 30)
        if ns.is_valid():
          self.app_apns_services[app_name].append(ns)
    else:
      count = apns_service_count - len(self.app_apns_services[app_name])
      if count > 0:
        for i in xrange(count):
          log.msg('After Add %dth APNSService for %s ' % (i, app_name))
          ns = APNSService(path_to_cert_or_cert, environment, app_name, 30)
          if ns.is_valid():
            self.app_apns_services[app_name].append(ns)

  def notify(self, app_name, token_or_token_list, aps_dict_or_list):
    try:
      data = encode_notifications(
        [t.replace(' ', '') for t in token_or_token_list]
        if (type(token_or_token_list) is list)
        else token_or_token_list.replace(' ', ''),
        aps_dict_or_list)

      apns_service = self.apns_service(app_name)
      if apns_service is not None:
        d = apns_service.write(data)
      else:
        log.msg('NO valid APNSService for %S' % app_name)
    except:
      pass


  def feedback(self, app_id):
    def _cb(r):
        x = decode_feedback(r)
        log.msg("FEEDBACK:", x)
        return x
    return self.apns_service(app_id).read().addCallback(_cb)

  def parse_data(self):
    while True:
      l = len(self.data)
      if l < 4: return
      lm = parse_netint(self.data[:4])
      if l - 4 < lm:
        return
      p = self.data[4:lm+4]
      self.data=self.data[lm+4:]
      jd = None
      try:
        jd = json.loads(p)
      except:
        pass
      if not jd: continue
      if (jd.get("cmd") == "provision"):
        self.provision(jd.get("app_id"),
                       jd.get("cert"),
                       jd.get("env"))
      elif (jd.get("cmd") == "notify"):
        self.sent_count = self.sent_count + 1
        self.notify(jd.get("app_id"),
                    jd.get("tokens"),
                    jd.get("notify"))
        if self.sent_count < 5000: continue
        self.sent_count = 0
        self.feedback(jd.get("app_id"))
      #endif

  def dataReceived(self, data):
    self.data = self.data + data
    self.parse_data()
    #self.transport.write(data)

class P4Factory(protocol.Factory):
  def buildProtocol(self, addr):
    return P4Server()
