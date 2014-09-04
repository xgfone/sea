# coding: utf-8
import sys
import logging

import routes
import eventlet
from oslo.config import cfg

from sea import wsgi
from sea import service
from sea.utils import log

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

host_opts = [
    cfg.StrOpt('host', default="0.0.0.0", help='Host ip'),
    cfg.IntOpt('port', default=60000, help='Host port')
]

CONF.register_opts(host_opts)


class HelloController(wsgi.Controller):
    def hello(self, req):
        return "Hello"


class API(wsgi.Router):
    def __init__(self):
        mapper = routes.Mapper()
        mapper.redirect("", "/")

        resource = wsgi.Resource(HelloController())
        mapper.connect("/hello",
                       controller=resource,
                       action="hello",
                       conditions={"method": ['GET']})

        super(API, self).__init__(mapper)


class Server(service.Service):
    def __init__(self, name, app, host='0.0.0.0', port=None):
        self.name = name
        self.app = app
        self.host = host
        self.port = port
        self.server = wsgi.Server(self.name, self.app, host=self.host, port=self.port)

    def start(self):
        self.server.start()

    def stop(self):
        self.server.stop()

    def wait(self):
        self.server.wait()


def main():
    CONF(sys.argv[1:], project='example', version='1.0')
    log.setup()
    eventlet.monkey_patch(all=True)

    app = API()
    #server = Server("example", app, host=CONF.host, port=CONF.port)
    server = wsgi.Server("example", app, host=CONF.host, port=CONF.port)
    lancher = service.launch(server, workers=1)
    lancher.wait()


if __name__ == "__main__":
    main()
