from cgi import parse_qs
from cgi import escape
import logging
from pprint import pprint

def hello_world(environ, start_response):
    parameters = parse_qs(environ.get('QUERY_STRING', ''))

    if 'subject' in parameters:
        subject = escape(parameters['subject'][0])
    else:
        subject = 'World.'

    pprint(environ)
    start_response('200 OK', [('Context-Type', 'text/html')])
    return ['''Hello %(subject)s
    Hello %(subject)s!''' %{'subject': subject}]


if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    IP = 'localhost'
    port = 8080
    server = make_server(IP, port, hello_world)
    logging.basicConfig(level=logging.INFO)
    LOG = logging.getLogger('wsgi')
    LOG.info('listening on %s: %d'%(IP, port))
    server.serve_forever()