#-*- python -*-
#-*- coding: utf-8 -*-
from twisted.application import internet, service
from pyapns.server import P4Factory
application = service.Application("echo")
p4Service = internet.TCPServer(8000, P4Factory())
p4Service.setServiceParent(application)
