from zope.interface import implements
from twisted.application.service import IServiceMaker
from twisted.application import internet
from twisted.plugin import IPlugin
from twisted.python import usage
from pyapns.server import P4Factory

class Options(usage.Options):
    optParameters = [["port", "P", 7077, "The port number to listen on."]]

class P4ServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "APNS-P4"
    description = "A TCP-based ANPS Proxy server."
    options = Options
    def makeService(self, options):
        return internet.TCPServer(int(options["port"]), P4Factory())

serviceMaker = P4ServiceMaker()
