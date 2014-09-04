# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 IBM Corp.
# Copyright 2011 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import sys
import json
import socket
import inspect
import os.path
from xml.dom import minidom
import ssl
import math
import time

from lxml import etree
import greenlet
import eventlet
import eventlet.wsgi
import routes.middleware
import webob
import webob.dec
import webob.exc
from oslo.config import cfg

from sea.utils import xml as xmlutils
from sea.utils import gettext as gettextutils
from sea.utils import log as logging
from sea import exception

try:
    from sea.utils.gettext import _
except ImportError:
    _ = lambda v: v

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

XMLNS_V10 = 'http://docs.rackspacecloud.com/servers/api/v1.0'
XMLNS_V11 = 'http://docs.openstack.org/compute/api/v1.1'

# The vendor content types should serialize identically to the non-vendor
# content types. So to avoid littering the code with both options, we
# map the vendor to the other when looking up the type
_CONTENT_TYPE_MAP = {
    'json': 'application/json',
    'xml': 'application/xml',
}

_MEDIA_TYPE_MAP = {
    'application/json': 'json',
    'application/xml': 'xml',
    'application/atom': 'atom',
}

# These are typically automatically created by routes as either defaults
# collection or member methods.
_ROUTES_METHODS = [
    'create',
    'delete',
    'show',
    'update',
]

_SUPPORTED_CONTENT_TYPES = [
    'application/json',
    'application/xml',
]


class Controller(object):
    """Default controller."""
    pass


class Request(webob.Request):
    """Add some OpenStack API-specific logic to the base webob.Request."""

    def __init__(self, *args, **kwargs):
        super(Request, self).__init__(*args, **kwargs)

    def get_content_type(self):
        """Determine content type of the request body.

        Does not do any body introspection, only checks header

        """
        if "Content-Type" not in self.headers:
            return None

        content_type = self.content_type

        # NOTE(markmc): text/plain is the default for eventlet and
        # other webservers which use mimetools.Message.gettype()
        # whereas twisted defaults to ''.
        if not content_type or content_type == 'text/plain':
            return None

        if content_type not in _SUPPORTED_CONTENT_TYPES:
            raise exception.InvalidContentType(content_type=content_type)

        return content_type

    def best_match_content_type(self):
        """Determine the requested response content-type."""
        if 'nova.best_content_type' not in self.environ:
            # Calculate the best MIME type
            content_type = None

            # Check URL path suffix
            parts = self.path.rsplit('.', 1)
            if len(parts) > 1:
                possible_type = 'application/' + parts[1]
                if possible_type in _SUPPORTED_CONTENT_TYPES:
                    content_type = possible_type

            if not content_type:
                content_type = self.accept.best_match(_SUPPORTED_CONTENT_TYPES)

            self.environ['best_content_type'] = (content_type or 'application/json')

        return self.environ['best_content_type']

    def best_match_language(self):
        """Determine the best available language for the request.

        :returns: the best language match or None if the 'Accept-Language'
                  header was not available in the request.
        """
        if not self.accept_language:
            return None
        return self.accept_language.best_match(gettextutils.get_available_languages('nova'))


class Server(object):
    """Server class to manage a WSGI server, serving a WSGI application."""

    default_pool_size = 1000

    def __init__(self, name, app, host='0.0.0.0', port=0, pool_size=None,
                 protocol=eventlet.wsgi.HttpProtocol, backlog=128,
                 use_ssl=False, max_url_len=None,
                 ca_file=None, cert_file=None, key_file=None):
        """Initialize, but do not start, a WSGI server.

        :param name: Pretty name for logging.
        :param app: The WSGI application to serve.
        :param host: IP address to serve the application.
        :param port: Port number to server the application.
        :param pool_size: Maximum number of eventlets to spawn concurrently.
        :param backlog: Maximum number of queued connections.
        :param max_url_len: Maximum length of permitted URLs.
        :returns: None
        :raises: nova.exception.InvalidInput
        """
        self.name = name
        self.app = app
        self._server = None
        self._protocol = protocol
        self._pool = eventlet.GreenPool(pool_size or self.default_pool_size)
        self._logger = logging.getLogger("nova.%s.wsgi.server" % self.name)
        self._wsgi_logger = logging.WritableLogger(self._logger)
        self._use_ssl = use_ssl
        self._max_url_len = max_url_len
        self._ca_file = ca_file
        self._cert_file = cert_file
        self._key_file = key_file

        if backlog < 1:
            raise exception.InvalidInput(reason='The backlog must be more than 1')

        bind_addr = (host, port)
        # TODO(dims): eventlet's green dns/socket module does not actually
        # support IPv6 in getaddrinfo(). We need to get around this in the
        # future or monitor upstream for a fix
        try:
            info = socket.getaddrinfo(bind_addr[0],
                                      bind_addr[1],
                                      socket.AF_UNSPEC,
                                      socket.SOCK_STREAM)[0]
            family = info[0]
            bind_addr = info[-1]
        except Exception:
            family = socket.AF_INET

        self._socket = eventlet.listen(bind_addr, family, backlog=backlog)
        (self.host, self.port) = self._socket.getsockname()[0:2]
        LOG.info(_("%(name)s listening on %(host)s:%(port)s") % self.__dict__)

    def start(self):
        """Start serving a WSGI application.

        :returns: None
        """
        if self._use_ssl:
            try:
                ca_file = self._ca_file
                cert_file = self._cert_file
                key_file = self._key_file

                if cert_file and not os.path.exists(cert_file):
                    raise RuntimeError(_("Unable to find cert_file : %s") % cert_file)

                if ca_file and not os.path.exists(ca_file):
                    raise RuntimeError(_("Unable to find ca_file : %s") % ca_file)

                if key_file and not os.path.exists(key_file):
                    raise RuntimeError(_("Unable to find key_file : %s") % key_file)

                if self._use_ssl and (not cert_file or not key_file):
                    raise RuntimeError(_("When running server in SSL mode, you must "
                                       "specify both a cert_file and key_file "
                                       "option value in your configuration file"))
                ssl_kwargs = {
                    'server_side': True,
                    'certfile': cert_file,
                    'keyfile': key_file,
                    'cert_reqs': ssl.CERT_NONE,
                }

                if ca_file:
                    ssl_kwargs['ca_certs'] = ca_file
                    ssl_kwargs['cert_reqs'] = ssl.CERT_REQUIRED

                self._socket = eventlet.wrap_ssl(self._socket,
                                                 **ssl_kwargs)

                self._socket.setsockopt(socket.SOL_SOCKET,
                                        socket.SO_REUSEADDR, 1)
                # sockets can hang around forever without keepalive
                self._socket.setsockopt(socket.SOL_SOCKET,
                                        socket.SO_KEEPALIVE, 1)

                # This option isn't available in the OS X version of eventlet
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    self._socket.setsockopt(socket.IPPROTO_TCP,
                                            socket.TCP_KEEPIDLE)

            except Exception as err:
                LOG.error(_("Failed to start %(name)s on %(host)s"
                            ":%(port)s with SSL support") % self.__dict__)
                raise err

        wsgi_kwargs = {
            'func': eventlet.wsgi.server,
            'sock': self._socket,
            'site': self.app,
            'protocol': self._protocol,
            'custom_pool': self._pool,
            'log': self._wsgi_logger,
        }

        if self._max_url_len:
            wsgi_kwargs['url_length_limit'] = self._max_url_len

        self._server = eventlet.spawn(**wsgi_kwargs)

    def stop(self):
        """Stop this server.

        This is not a very nice action, as currently the method by which a
        server is stopped is by killing its eventlet.

        :returns: None

        """
        LOG.info(_("Stopping WSGI server."))

        if self._server is not None:
            # Resize pool to stop new requests from being processed
            self._pool.resize(0)
            self._server.kill()

    def wait(self):
        """Block, until the server has stopped.

        Waits on the server's eventlet to finish, then returns.

        :returns: None

        """
        try:
            self._server.wait()
        except greenlet.GreenletExit:
            LOG.info(_("WSGI server has stopped."))


class Application(object):
    """Base WSGI application wrapper. Subclasses need to implement __call__."""

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [app:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [app:wadl]
            latest_version = 1.3
            paste.app_factory = nova.api.fancy_api:Wadl.factory

        which would result in a call to the `Wadl` class as

            import nova.api.fancy_api
            fancy_api.Wadl(latest_version='1.3')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        return cls(**local_config)

    def __call__(self, environ, start_response):
        r"""Subclasses will probably want to implement __call__ like this:

        @webob.dec.wsgify(RequestClass=Request)
        def __call__(self, req):
          # Any of the following objects work as responses:

          # Option 1: simple string
          res = 'message\n'

          # Option 2: a nicely formatted HTTP exception page
          res = exc.HTTPForbidden(detail='Nice try')

          # Option 3: a webob Response object (in case you need to play with
          # headers, or you want to be treated like an iterable, or or or)
          res = Response();
          res.app_iter = open('somefile')

          # Option 4: any wsgi app to be run next
          res = self.application

          # Option 5: you can get a Response object for a wsgi app, too, to
          # play with headers etc
          res = req.get_response(self.application)

          # You can then just return your response...
          return res
          # ... or set req.response and return None.
          req.response = res

        See the end of http://pythonpaste.org/webob/modules/dec.html
        for more info.

        """
        raise NotImplementedError(_('You must implement __call__'))


class Middleware(Application):
    """Base WSGI middleware.

    These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.

    """

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [filter:analytics]
            redis_host = 127.0.0.1
            paste.filter_factory = nova.api.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import nova.api.analytics
            analytics.Analytics(app_from_paste, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            return cls(app, **local_config)
        return _factory

    def __init__(self, application):
        self.application = application

    def process_request(self, req):
        """Called on each request.

        If this returns None, the next application down the stack will be
        executed. If it returns a response then that response will be returned
        and execution will stop here.

        """
        return None

    def process_response(self, response):
        """Do whatever you'd like to the response."""
        return response

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        response = self.process_request(req)
        if response:
            return response
        response = req.get_response(self.application)
        return self.process_response(response)


class Debug(Middleware):
    """Helper class for debugging a WSGI application.

    Can be inserted into any WSGI application chain to get information
    about the request and response.

    """

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        print(('*' * 40) + ' REQUEST ENVIRON')
        for key, value in req.environ.items():
            print(key, '=', value)
        print()
        resp = req.get_response(self.application)

        print(('*' * 40) + ' RESPONSE HEADERS')
        for (key, value) in resp.headers.iteritems():
            print(key, '=', value)
        print

        resp.app_iter = self.print_generator(resp.app_iter)

        return resp

    @staticmethod
    def print_generator(app_iter):
        """Iterator that prints the contents of a wrapper string."""
        print(('*' * 40) + ' BODY')
        for part in app_iter:
            sys.stdout.write(part)
            sys.stdout.flush()
            yield part
        print()


class Router(object):
    """WSGI middleware that maps incoming requests to WSGI apps."""

    def __init__(self, mapper):
        """Create a router for the given routes.Mapper.

        Each route in `mapper` must specify a 'controller', which is a
        WSGI app to call.  You'll probably want to specify an 'action' as
        well and have your controller be an object that can route
        the request to the action-specific method.

        Examples:
          mapper = routes.Mapper()
          sc = ServerController()

          # Explicit mapping of one route to a controller+action
          mapper.connect(None, '/svrlist', controller=sc, action='list')

          # Actions are all implicitly defined
          mapper.resource('server', 'servers', controller=sc)

          # Pointing to an arbitrary WSGI app.  You can specify the
          # {path_info:.*} parameter so the target app can be handed just that
          # section of the URL.
          mapper.connect(None, '/v1.0/{path_info:.*}', controller=BlogApp())

        """
        self.map = mapper
        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          self.map)

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """Route the incoming request to a controller based on self.map.

        If no match, return a 404.

        """
        return self._router

    @staticmethod
    @webob.dec.wsgify(RequestClass=Request)
    def _dispatch(req):
        """Dispatch the request to the appropriate controller.

        Called by self._router after matching the incoming request to a route
        and putting the information into req.environ.  Either returns 404
        or the routed WSGI app's response.

        """
        match = req.environ['wsgiorg.routing_args'][1]
        if not match:
            return webob.exc.HTTPNotFound()
        app = match['controller']
        return app


class Loader(object):
    """Used to load WSGI applications from paste configurations."""

    def __init__(self, config_path):
        """Initialize the loader, and attempt to find the config.

        :param config_path: Full or relative path to the paste config.
        :returns: None

        """
        if os.path.exists(config_path):
            self.config_path = config_path
        else:
            self.config_path = CONF.find_file(config_path)
        if not self.config_path:
            raise exception.ConfigNotFound(path=config_path)

    def load_app(self, name):
        """Return the paste URLMap wrapped WSGI application.

        :param name: Name of the application to load.
        :returns: Paste URLMap object wrapping the requested application.
        :raises: `nova.exception.PasteAppNotFound`

        """
        try:
            LOG.debug(_("Loading app %(name)s from %(path)s") %
                      {'name': name, 'path': self.config_path})
            #return deploy.loadapp("config:%s" % self.config_path, name=name)
        except LookupError as err:
            LOG.error(err)
            raise exception.PasteAppNotFound(name=name, path=self.config_path)


class ActionDispatcher(object):
    """Maps method name to local methods through action name."""

    def dispatch(self, *args, **kwargs):
        """Find and call local method."""
        action = kwargs.pop('action', 'default')
        action_method = getattr(self, str(action), self.default)
        return action_method(*args, **kwargs)

    def default(self, data):
        raise NotImplementedError()


class TextDeserializer(ActionDispatcher):
    """Default request body deserialization."""

    def deserialize(self, datastring, action='default'):
        return self.dispatch(datastring, action=action)

    def default(self, datastring):
        return {}


class JSONDeserializer(TextDeserializer):

    def _from_json(self, datastring):
        try:
            return json.loads(datastring)
        except ValueError:
            msg = _("cannot understand JSON")
            raise exception.MalformedRequestBody(reason=msg)

    def default(self, datastring):
        return {'body': self._from_json(datastring)}


class XMLDeserializer(TextDeserializer):

    def __init__(self, metadata=None):
        """
        :param metadata: information needed to deserialize xml into
                         a dictionary.
        """
        super(XMLDeserializer, self).__init__()
        self.metadata = metadata or {}

    def _from_xml(self, datastring):
        plurals = set(self.metadata.get('plurals', {}))
        node = xmlutils.safe_minidom_parse_string(datastring).childNodes[0]
        return {node.nodeName: self._from_xml_node(node, plurals)}

    def _from_xml_node(self, node, listnames):
        """Convert a minidom node to a simple Python type.

        :param listnames: list of XML node names whose subnodes should
                          be considered list items.

        """
        if len(node.childNodes) == 1 and node.childNodes[0].nodeType == 3:
            return node.childNodes[0].nodeValue
        elif node.nodeName in listnames:
            return [self._from_xml_node(n, listnames) for n in node.childNodes]
        else:
            result = dict()
            for attr in node.attributes.keys():
                if not attr.startswith("xmlns"):
                    result[attr] = node.attributes[attr].nodeValue
            for child in node.childNodes:
                if child.nodeType != node.TEXT_NODE:
                    result[child.nodeName] = self._from_xml_node(child,
                                                                 listnames)
            return result

    def find_first_child_named_in_namespace(self, parent, namespace, name):
        """Search a nodes children for the first child with a given name."""
        for node in parent.childNodes:
            if (node.localName == name and
                node.namespaceURI and
                    node.namespaceURI == namespace):
                return node
        return None

    def find_first_child_named(self, parent, name):
        """Search a nodes children for the first child with a given name."""
        for node in parent.childNodes:
            if node.localName == name:
                return node
        return None

    def find_children_named(self, parent, name):
        """Return all of a nodes children who have the given name."""
        for node in parent.childNodes:
            if node.localName == name:
                yield node

    def extract_text(self, node):
        """Get the text field contained by the given node."""
        ret_val = ""
        for child in node.childNodes:
            if child.nodeType == child.TEXT_NODE:
                ret_val += child.nodeValue
        return ret_val

    def extract_elements(self, node):
        """Get only Element type childs from node."""
        elements = []
        for child in node.childNodes:
            if child.nodeType == child.ELEMENT_NODE:
                elements.append(child)
        return elements

    def find_attribute_or_element(self, parent, name):
        """Get an attribute value; fallback to an element if not found."""
        if parent.hasAttribute(name):
            return parent.getAttribute(name)

        node = self.find_first_child_named(parent, name)
        if node:
            return self.extract_text(node)

        return None

    def default(self, datastring):
        return {'body': self._from_xml(datastring)}


class MetadataXMLDeserializer(XMLDeserializer):

    def extract_metadata(self, metadata_node):
        """Marshal the metadata attribute of a parsed request."""
        metadata = {}
        if metadata_node is not None:
            for meta_node in self.find_children_named(metadata_node, "meta"):
                key = meta_node.getAttribute("key")
                metadata[key] = self.extract_text(meta_node)
        return metadata


class DictSerializer(ActionDispatcher):
    """Default request body serialization."""

    def serialize(self, data, action='default'):
        return self.dispatch(data, action=action)

    def default(self, data):
        return ""


class JSONDictSerializer(DictSerializer):
    """Default JSON request body serialization."""

    def default(self, data):
        return json.dumps(data)


class XMLDictSerializer(DictSerializer):

    def __init__(self, metadata=None, xmlns=None):
        """
        :param metadata: information needed to deserialize xml into
                         a dictionary.
        :param xmlns: XML namespace to include with serialized xml
        """
        super(XMLDictSerializer, self).__init__()
        self.metadata = metadata or {}
        self.xmlns = xmlns

    def default(self, data):
        # We expect data to contain a single key which is the XML root.
        root_key = data.keys()[0]
        doc = minidom.Document()
        node = self._to_xml_node(doc, self.metadata, root_key, data[root_key])

        return self.to_xml_string(node)

    def to_xml_string(self, node, has_atom=False):
        self._add_xmlns(node, has_atom)
        return node.toxml('UTF-8')

    #NOTE (ameade): the has_atom should be removed after all of the
    # xml serializers and view builders have been updated to the current
    # spec that required all responses include the xmlns:atom, the has_atom
    # flag is to prevent current tests from breaking
    def _add_xmlns(self, node, has_atom=False):
        if self.xmlns is not None:
            node.setAttribute('xmlns', self.xmlns)
        if has_atom:
            node.setAttribute('xmlns:atom', "http://www.w3.org/2005/Atom")

    def _to_xml_node(self, doc, metadata, nodename, data):
        """Recursive method to convert data members to XML nodes."""
        result = doc.createElement(nodename)

        # Set the xml namespace if one is specified
        # TODO(justinsb): We could also use prefixes on the keys
        xmlns = metadata.get('xmlns', None)
        if xmlns:
            result.setAttribute('xmlns', xmlns)

        #TODO(bcwaldon): accomplish this without a type-check
        if isinstance(data, list):
            collections = metadata.get('list_collections', {})
            if nodename in collections:
                metadata = collections[nodename]
                for item in data:
                    node = doc.createElement(metadata['item_name'])
                    node.setAttribute(metadata['item_key'], str(item))
                    result.appendChild(node)
                return result
            singular = metadata.get('plurals', {}).get(nodename, None)
            if singular is None:
                if nodename.endswith('s'):
                    singular = nodename[:-1]
                else:
                    singular = 'item'
            for item in data:
                node = self._to_xml_node(doc, metadata, singular, item)
                result.appendChild(node)
        #TODO(bcwaldon): accomplish this without a type-check
        elif isinstance(data, dict):
            collections = metadata.get('dict_collections', {})
            if nodename in collections:
                metadata = collections[nodename]
                for k, v in data.items():
                    node = doc.createElement(metadata['item_name'])
                    node.setAttribute(metadata['item_key'], str(k))
                    text = doc.createTextNode(str(v))
                    node.appendChild(text)
                    result.appendChild(node)
                return result
            attrs = metadata.get('attributes', {}).get(nodename, {})
            for k, v in data.items():
                if k in attrs:
                    result.setAttribute(k, str(v))
                else:
                    if k == "deleted":
                        v = str(bool(v))
                    node = self._to_xml_node(doc, metadata, k, v)
                    result.appendChild(node)
        else:
            # Type is atom
            node = doc.createTextNode(str(data))
            result.appendChild(node)
        return result

    def _create_link_nodes(self, xml_doc, links):
        link_nodes = []
        for link in links:
            link_node = xml_doc.createElement('atom:link')
            link_node.setAttribute('rel', link['rel'])
            link_node.setAttribute('href', link['href'])
            if 'type' in link:
                link_node.setAttribute('type', link['type'])
            link_nodes.append(link_node)
        return link_nodes

    def _to_xml(self, root):
        """Convert the xml object to an xml string."""
        return etree.tostring(root, encoding='UTF-8', xml_declaration=True)


def serializers(**serializers):
    """Attaches serializers to a method.

    This decorator associates a dictionary of serializers with a
    method.  Note that the function attributes are directly
    manipulated; the method is not wrapped.
    """

    def decorator(func):
        if not hasattr(func, 'wsgi_serializers'):
            func.wsgi_serializers = {}
        func.wsgi_serializers.update(serializers)
        return func
    return decorator


def deserializers(**deserializers):
    """Attaches deserializers to a method.

    This decorator associates a dictionary of deserializers with a
    method.  Note that the function attributes are directly
    manipulated; the method is not wrapped.
    """

    def decorator(func):
        if not hasattr(func, 'wsgi_deserializers'):
            func.wsgi_deserializers = {}
        func.wsgi_deserializers.update(deserializers)
        return func
    return decorator


def response(code):
    """Attaches response code to a method.

    This decorator associates a response code with a method.  Note
    that the function attributes are directly manipulated; the method
    is not wrapped.
    """

    def decorator(func):
        func.wsgi_code = code
        return func
    return decorator


class ResponseObject(object):
    """Bundles a response object with appropriate serializers.

    Object that app methods may return in order to bind alternate
    serializers with a response object to be serialized.  Its use is
    optional.
    """

    def __init__(self, obj, code=None, headers=None, **serializers):
        """Binds serializers with an object.

        Takes keyword arguments akin to the @serializer() decorator
        for specifying serializers.  Serializers specified will be
        given preference over default serializers or method-specific
        serializers on return.
        """

        self.obj = obj
        self.serializers = serializers
        self._default_code = 200
        self._code = code
        self._headers = headers or {}
        self.serializer = None
        self.media_type = None

    def __getitem__(self, key):
        """Retrieves a header with the given name."""

        return self._headers[key.lower()]

    def __setitem__(self, key, value):
        """Sets a header with the given name to the given value."""

        self._headers[key.lower()] = value

    def __delitem__(self, key):
        """Deletes the header with the given name."""

        del self._headers[key.lower()]

    def _bind_method_serializers(self, meth_serializers):
        """Binds method serializers with the response object.

        Binds the method serializers with the response object.
        Serializers specified to the constructor will take precedence
        over serializers specified to this method.

        :param meth_serializers: A dictionary with keys mapping to
                                 response types and values containing
                                 serializer objects.
        """

        # We can't use update because that would be the wrong
        # precedence
        for mtype, serializer in meth_serializers.items():
            self.serializers.setdefault(mtype, serializer)

    def get_serializer(self, content_type, default_serializers=None):
        """Returns the serializer for the wrapped object.

        Returns the serializer for the wrapped object subject to the
        indicated content type.  If no serializer matching the content
        type is attached, an appropriate serializer drawn from the
        default serializers will be used.  If no appropriate
        serializer is available, raises InvalidContentType.
        """

        default_serializers = default_serializers or {}

        try:
            mtype = _MEDIA_TYPE_MAP.get(content_type, content_type)
            if mtype in self.serializers:
                return mtype, self.serializers[mtype]
            else:
                return mtype, default_serializers[mtype]
        except (KeyError, TypeError):
            raise exception.InvalidContentType(content_type=content_type)

    def preserialize(self, content_type, default_serializers=None):
        """Prepares the serializer that will be used to serialize.

        Determines the serializer that will be used and prepares an
        instance of it for later call.  This allows the serializer to
        be accessed by extensions for, e.g., template extension.
        """

        mtype, serializer = self.get_serializer(content_type,
                                                default_serializers)
        self.media_type = mtype
        self.serializer = serializer()

    def attach(self, **kwargs):
        """Attach slave templates to serializers."""

        if self.media_type in kwargs:
            self.serializer.attach(kwargs[self.media_type])

    def serialize(self, request, content_type, default_serializers=None):
        """Serializes the wrapped object.

        Utility method for serializing the wrapped object.  Returns a
        webob.Response object.
        """

        if self.serializer:
            serializer = self.serializer
        else:
            _mtype, _serializer = self.get_serializer(content_type,
                                                      default_serializers)
            serializer = _serializer()

        response = webob.Response()
        response.status_int = self.code
        for hdr, value in self._headers.items():
            response.headers[hdr] = str(value)
        response.headers['Content-Type'] = content_type
        if self.obj is not None:
            response.body = serializer.serialize(self.obj)

        return response

    @property
    def code(self):
        """Retrieve the response status."""

        return self._code or self._default_code

    @property
    def headers(self):
        """Retrieve the headers."""

        return self._headers.copy()


def action_peek_json(body):
    """Determine action to invoke."""

    try:
        decoded = json.loads(body)
    except ValueError:
        msg = _("cannot understand JSON")
        raise exception.MalformedRequestBody(reason=msg)

    # Make sure there's exactly one key...
    if len(decoded) != 1:
        msg = _("too many body keys")
        raise exception.MalformedRequestBody(reason=msg)

    # Return the action and the decoded body...
    return decoded.keys()[0]


def action_peek_xml(body):
    """Determine action to invoke."""

    dom = xmlutils.safe_minidom_parse_string(body)
    action_node = dom.childNodes[0]

    return action_node.tagName


class Resource(Application):
    """WSGI app that handles (de)serialization and controller dispatch.

    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon its controller.  All
    controller action methods must accept a 'req' argument, which is the
    incoming wsgi.Request. If the operation is a PUT or POST, the controller
    method must also accept a 'body' argument (the deserialized request body).
    They may raise a webob.exc exception or return a dict, which will be
    serialized by requested content type.

    Exceptions derived from webob.exc.HTTPException will be automatically
    wrapped in Fault() to provide API friendly error responses.

    """

    def __init__(self, controller, action_peek=None, inherits=None,
                 **deserializers):
        """
        :param controller: object that implement methods created by routes lib
        :param action_peek: dictionary of routines for peeking into an action
                            request body to determine the desired action
        :param inherits: another resource object that this resource should
                         inherit extensions from. Any action extensions that
                         are applied to the parent resource will also apply
                         to this resource.
        """

        self.controller = controller

        default_deserializers = dict(xml=XMLDeserializer,
                                     json=JSONDeserializer)
        default_deserializers.update(deserializers)

        self.default_deserializers = default_deserializers
        self.default_serializers = dict(xml=XMLDictSerializer,
                                        json=JSONDictSerializer)

        self.action_peek = dict(json=action_peek_json)
        self.action_peek.update(action_peek or {})

        # Copy over the actions dictionary
        self.wsgi_actions = {}
        if controller:
            self.register_actions(controller)

        # Save a mapping of extensions
        self.wsgi_extensions = {}
        self.wsgi_action_extensions = {}
        self.inherits = inherits

    def register_actions(self, controller):
        """Registers controller actions with this resource."""

        actions = getattr(controller, 'wsgi_actions', {})
        for key, method_name in actions.items():
            self.wsgi_actions[key] = getattr(controller, method_name)

    def register_extensions(self, controller):
        """Registers controller extensions with this resource."""

        extensions = getattr(controller, 'wsgi_extensions', [])
        for method_name, action_name in extensions:
            # Look up the extending method
            extension = getattr(controller, method_name)

            if action_name:
                # Extending an action...
                if action_name not in self.wsgi_action_extensions:
                    self.wsgi_action_extensions[action_name] = []
                self.wsgi_action_extensions[action_name].append(extension)
            else:
                # Extending a regular method
                if method_name not in self.wsgi_extensions:
                    self.wsgi_extensions[method_name] = []
                self.wsgi_extensions[method_name].append(extension)

    def get_action_args(self, request_environment):
        """Parse dictionary created by routes library."""

        # NOTE(Vek): Check for get_action_args() override in the
        # controller
        if hasattr(self.controller, 'get_action_args'):
            return self.controller.get_action_args(request_environment)

        try:
            args = request_environment['wsgiorg.routing_args'][1].copy()
        except (KeyError, IndexError, AttributeError):
            return {}

        try:
            del args['controller']
        except KeyError:
            pass

        try:
            del args['format']
        except KeyError:
            pass

        return args

    def get_body(self, request):
        try:
            content_type = request.get_content_type()
        except exception.InvalidContentType:
            LOG.debug(_("Unrecognized Content-Type provided in request"))
            return None, ''

        if not content_type:
            LOG.debug(_("No Content-Type provided in request"))
            return None, ''

        if len(request.body) <= 0:
            LOG.debug(_("Empty body provided in request"))
            return None, ''

        return content_type, request.body

    def deserialize(self, meth, content_type, body):
        meth_deserializers = getattr(meth, 'wsgi_deserializers', {})
        try:
            mtype = _MEDIA_TYPE_MAP.get(content_type, content_type)
            if mtype in meth_deserializers:
                deserializer = meth_deserializers[mtype]
            else:
                deserializer = self.default_deserializers[mtype]
        except (KeyError, TypeError):
            raise exception.InvalidContentType(content_type=content_type)

        if (hasattr(deserializer, 'want_controller')
                and deserializer.want_controller):
            return deserializer(self.controller).deserialize(body)
        else:
            return deserializer().deserialize(body)

    def pre_process_extensions(self, extensions, request, action_args):
        # List of callables for post-processing extensions
        post = []

        for ext in extensions:
            if inspect.isgeneratorfunction(ext):
                response = None

                # If it's a generator function, the part before the
                # yield is the preprocessing stage
                try:
                    with ResourceExceptionHandler():
                        gen = ext(req=request, **action_args)
                        response = gen.next()
                except Fault as ex:
                    response = ex

                # We had a response...
                if response:
                    return response, []

                # No response, queue up generator for post-processing
                post.append(gen)
            else:
                # Regular functions only perform post-processing
                post.append(ext)

        # Run post-processing in the reverse order
        return None, reversed(post)

    def post_process_extensions(self, extensions, resp_obj, request,
                                action_args):
        for ext in extensions:
            response = None
            if inspect.isgenerator(ext):
                # If it's a generator, run the second half of
                # processing
                try:
                    with ResourceExceptionHandler():
                        response = ext.send(resp_obj)
                except StopIteration:
                    # Normal exit of generator
                    continue
                except Fault as ex:
                    response = ex
            else:
                # Regular functions get post-processing...
                try:
                    with ResourceExceptionHandler():
                        response = ext(req=request, resp_obj=resp_obj,
                                       **action_args)
                except Fault as ex:
                    response = ex

            # We had a response...
            if response:
                return response

        return None

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        """WSGI method that controls (de)serialization and method dispatch."""

        # Identify the action, its arguments, and the requested
        # content type
        action_args = self.get_action_args(request.environ)
        action = action_args.pop('action', None)
        content_type, body = self.get_body(request)
        accept = request.best_match_content_type()

        # NOTE(Vek): Splitting the function up this way allows for
        #            auditing by external tools that wrap the existing
        #            function.  If we try to audit __call__(), we can
        #            run into troubles due to the @webob.dec.wsgify()
        #            decorator.
        return self._process_stack(request, action, action_args,
                                   content_type, body, accept)

    def _process_stack(self, request, action, action_args,
                       content_type, body, accept):
        """Implement the processing stack."""

        # Get the implementing method
        try:
            meth, extensions = self.get_method(request, action,
                                               content_type, body)
        except (AttributeError, TypeError):
            return Fault(webob.exc.HTTPNotFound())
        except KeyError as ex:
            msg = _("There is no such action: %s") % ex.args[0]
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))
        except exception.MalformedRequestBody:
            msg = _("Malformed request body")
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        if body:
            msg = _("Action: '%(action)s', body: "
                    "%(body)s") % {'action': action,
                                   'body': unicode(body, 'utf-8')}
            LOG.debug(msg)
        LOG.debug(_("Calling method %s") % str(meth))

        # Now, deserialize the request body...
        try:
            if content_type:
                contents = self.deserialize(meth, content_type, body)
            else:
                contents = {}
        except exception.InvalidContentType:
            msg = _("Unsupported Content-Type")
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))
        except exception.MalformedRequestBody:
            msg = _("Malformed request body")
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        # Update the action args
        action_args.update(contents)

        project_id = action_args.pop("project_id", None)
        context = request.environ.get('nova.context')
        if (context and project_id and (project_id != context.project_id)):
            msg = _("Malformed request URL: URL's project_id '%(project_id)s'"
                    " doesn't match Context's project_id"
                    " '%(context_project_id)s'") % {'project_id': project_id,
                                                    'context_project_id': context.project_id}
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        # Run pre-processing extensions
        response, post = self.pre_process_extensions(extensions,
                                                     request, action_args)

        if not response:
            try:
                with ResourceExceptionHandler():
                    action_result = self.dispatch(meth, request, action_args)
            except Fault as ex:
                response = ex

        if not response:
            # No exceptions; convert action_result into a
            # ResponseObject
            resp_obj = None
            if type(action_result) is dict or action_result is None:
                resp_obj = ResponseObject(action_result)
            elif isinstance(action_result, ResponseObject):
                resp_obj = action_result
            else:
                response = action_result

            # Run post-processing extensions
            if resp_obj:
                # Do a preserialize to set up the response object
                serializers = getattr(meth, 'wsgi_serializers', {})
                resp_obj._bind_method_serializers(serializers)
                if hasattr(meth, 'wsgi_code'):
                    resp_obj._default_code = meth.wsgi_code
                resp_obj.preserialize(accept, self.default_serializers)

                # Process post-processing extensions
                response = self.post_process_extensions(post, resp_obj,
                                                        request, action_args)

            if resp_obj and not response:
                response = resp_obj.serialize(request, accept,
                                              self.default_serializers)

        if context and hasattr(response, 'headers'):
            response.headers.add('x-compute-request-id', context.request_id)

        return response

    def get_method(self, request, action, content_type, body):
        meth, extensions = self._get_method(request,
                                            action,
                                            content_type,
                                            body)
        if self.inherits:
            _meth, parent_ext = self.inherits.get_method(request,
                                                         action,
                                                         content_type,
                                                         body)
            extensions.extend(parent_ext)
        return meth, extensions

    def _get_method(self, request, action, content_type, body):
        """Look up the action-specific method and its extensions."""

        # Look up the method
        try:
            if not self.controller:
                meth = getattr(self, action)
            else:
                meth = getattr(self.controller, action)
        except AttributeError:
            if (not self.wsgi_actions or action not in _ROUTES_METHODS + ['action']):
                # Propagate the error
                raise
        else:
            return meth, self.wsgi_extensions.get(action, [])

        if action == 'action':
            # OK, it's an action; figure out which action...
            mtype = _MEDIA_TYPE_MAP.get(content_type)
            action_name = self.action_peek[mtype](body)
        else:
            action_name = action

        # Look up the action method
        return (self.wsgi_actions[action_name],
                self.wsgi_action_extensions.get(action_name, []))

    def dispatch(self, method, request, action_args):
        """Dispatch a call to the action-specific method."""

        return method(req=request, **action_args)


def action(name):
    """Mark a function as an action.

    The given name will be taken as the action key in the body.

    This is also overloaded to allow extensions to provide
    non-extending definitions of create and delete operations.
    """

    def decorator(func):
        func.wsgi_action = name
        return func
    return decorator


def extends(*args, **kwargs):
    """Indicate a function extends an operation.

    Can be used as either::

        @extends
        def index(...):
            pass

    or as::

        @extends(action='resize')
        def _action_resize(...):
            pass
    """

    def decorator(func):
        # Store enough information to find what we're extending
        func.wsgi_extends = (func.__name__, kwargs.get('action'))
        return func

    # If we have positional arguments, call the decorator
    if args:
        return decorator(*args)

    # OK, return the decorator instead
    return decorator


class ResourceExceptionHandler(object):
    """Context manager to handle Resource exceptions.

    Used when processing exceptions generated by API implementation
    methods (or their extensions).  Converts most exceptions to Fault
    exceptions, with the appropriate logging.
    """

    def __enter__(self):
        return None

    def __exit__(self, ex_type, ex_value, ex_traceback):
        if not ex_value:
            return True

        if isinstance(ex_value, exception.NotAuthorized):
            raise Fault(webob.exc.HTTPForbidden(explanation=ex_value.format_message()))
        elif isinstance(ex_value, exception.Invalid):
            raise Fault(exception.ConvertedException(code=ex_value.code,
                        explanation=ex_value.format_message()))

        # Under python 2.6, TypeError's exception value is actually a string,
        # so test # here via ex_type instead:
        # http://bugs.python.org/issue7853
        elif issubclass(ex_type, TypeError):
            exc_info = (ex_type, ex_value, ex_traceback)
            LOG.error(_('Exception handling resource: %s') % ex_value, exc_info=exc_info)
            raise Fault(webob.exc.HTTPBadRequest())
        elif isinstance(ex_value, Fault):
            LOG.info(_("Fault thrown: %s"), unicode(ex_value))
            raise ex_value
        elif isinstance(ex_value, webob.exc.HTTPException):
            LOG.info(_("HTTP exception thrown: %s"), unicode(ex_value))
            raise Fault(ex_value)

        # We didn't handle the exception
        return False


class Fault(webob.exc.HTTPException):
    """Wrap webob.exc.HTTPException to provide API friendly response."""

    _fault_names = {
        400: "badRequest",
        401: "unauthorized",
        403: "forbidden",
        404: "itemNotFound",
        405: "badMethod",
        409: "conflictingRequest",
        413: "overLimit",
        415: "badMediaType",
        429: "overLimit",
        501: "notImplemented",
        503: "serviceUnavailable"
    }

    def __init__(self, exception):
        """Create a Fault for the given webob.exc.exception."""
        self.wrapped_exc = exception
        for key, value in self.wrapped_exc.headers.items():
            self.wrapped_exc.headers[key] = str(value)
        self.status_int = exception.status_int

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """Generate a WSGI response based on the exception passed to ctor."""

        user_locale = req.best_match_language()
        # Replace the body with fault details.
        code = self.wrapped_exc.status_int
        fault_name = self._fault_names.get(code, "computeFault")
        explanation = self.wrapped_exc.explanation
        LOG.debug(_("Returning %(code)s to user: %(explanation)s"),
                  {'code': code, 'explanation': explanation})

        explanation = gettextutils.get_localized_message(explanation, user_locale)
        fault_data = {
            fault_name: {
                'code': code,
                'message': explanation}}
        if code == 413 or code == 429:
            retry = self.wrapped_exc.headers.get('Retry-After', None)
            if retry:
                fault_data[fault_name]['retryAfter'] = retry

        # 'code' is an attribute on the fault tag itself
        metadata = {'attributes': {fault_name: 'code'}}

        xml_serializer = XMLDictSerializer(metadata, XMLNS_V11)

        content_type = req.best_match_content_type()
        serializer = {
            'application/xml': xml_serializer,
            'application/json': JSONDictSerializer(),
        }[content_type]

        self.wrapped_exc.body = serializer.serialize(fault_data)
        self.wrapped_exc.content_type = content_type
        _set_request_id_header(req, self.wrapped_exc.headers)

        return self.wrapped_exc

    def __str__(self):
        return self.wrapped_exc.__str__()


class RateLimitFault(webob.exc.HTTPException):
    """
    Rate-limited request response.
    """

    def __init__(self, message, details, retry_time):
        """
        Initialize new `RateLimitFault` with relevant information.
        """
        hdrs = RateLimitFault._retry_after(retry_time)
        self.wrapped_exc = webob.exc.HTTPTooManyRequests(headers=hdrs)
        self.content = {
            "overLimit": {
                "code": self.wrapped_exc.status_int,
                "message": message,
                "details": details,
                "retryAfter": hdrs['Retry-After'],
            },
        }

    @staticmethod
    def _retry_after(retry_time):
        delay = int(math.ceil(retry_time - time.time()))
        retry_after = delay if delay > 0 else 0
        headers = {'Retry-After': '%d' % retry_after}
        return headers

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        """
        Return the wrapped exception with a serialized body conforming to our
        error format.
        """
        user_locale = request.best_match_language()
        content_type = request.best_match_content_type()
        metadata = {"attributes": {"overLimit": ["code", "retryAfter"]}}

        self.content['overLimit']['message'] = \
            gettextutils.get_localized_message(self.content['overLimit']['message'],
                                               user_locale)
        self.content['overLimit']['details'] = \
            gettextutils.get_localized_message(self.content['overLimit']['details'],
                                               user_locale)

        xml_serializer = XMLDictSerializer(metadata, XMLNS_V11)
        serializer = {
            'application/xml': xml_serializer,
            'application/json': JSONDictSerializer(),
        }[content_type]

        content = serializer.serialize(self.content)
        self.wrapped_exc.body = content
        self.wrapped_exc.content_type = content_type

        return self.wrapped_exc


def _set_request_id_header(req, headers):
    context = req.environ.get('nova.context')
    if context:
        headers['x-compute-request-id'] = context.request_id
