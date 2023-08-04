import errno
import io
import os
import signal
import socket
import sys
import threading


class Middleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)


class AuthenticationMiddleware(Middleware):
    def __call__(self, environ, start_response):
        if not self.authenticate(environ):
            status = '401 Unauthorized'
            response_headers = [('Content-type', 'text/plain')]
            start_response(status, response_headers)
            return [b'Authentication failed.']

        return super().__call__(environ, start_response)
    
    def authenticate(self, environ):
    # Implement authentication logic
    # Return True if authenticated, False otherwise
    # Eg. check for valid credentials in headers or cookies
        return True
    

class LoggingMiddleware(Middleware):
    def __call__(self, environ, start_response):
        self.log_request(environ)
        response = super().__call__(environ, start_response)
        self.log_response(environ, response)
        return response

    def log_request(self, environ):
        print("Request:", environ['REQUEST_METHOD'], environ['PATH_INFO'])

    def log_response(self, environ, response):
        print("Response:", response)



class RequestModificationMiddleware(Middleware):
    def __call__(self, environ, start_response):
        environ['HTTP_X_CUSTOM_HEADER'] = 'Custom Value'
        return super().__call__(environ, start_response)


class ResponseModificationMiddleware(Middleware):
    def __call__(self, environ, start_response):
        response = super().__call__(environ, start_response)
        new_response_headers = [('Custom-Header', 'Custom Value')]
        return self.response_with_headers(response, new_response_headers)

    def response_with_headers(self, response, headers):
        status, response_headers = response[0], response[1]
        for header in headers:
            response_headers.append(header)
        return (status, response_headers) + response[2:]


class CachingMiddleware(Middleware):
    cache = {}

    def __call__(self, environ, start_response):
        cache_key = environ['REQUEST_METHOD'] + ":" + environ['PATH_INFO']

        if cache_key in self.cache:
            return self.cache[cache_key]

        response = super().__call__(environ, start_response)
        self.cache[cache_key] = response
        return response


class SecurityMiddleware(Middleware):
    def __call__(self, environ, start_response):
        if not self.is_secure_request(environ):
            status = '403 Forbidden'
            response_headers = [('Content-type', 'text/plain')]
            start_response(status, response_headers)
            return [b'Access denied.']

        return super().__call__(environ, start_response)

    def is_secure_request(self, environ):
        # Implement security checks 
        # Return True if the request is secure, False otherwise
        return True


class WSGIServer(object):
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    request_queue_size = 1

    def __init__(self, server_address) -> None:
        self.listen_socket = listen_socket = socket.socket(
            self.address_family, self.socket_type
        )

        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind(server_address)
        listen_socket.listen(self.request_queue_size)
        host, port = self.listen_socket.getsockname()[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port
        self.headers_set = []

        self.routing_table = {}
        self.middleware_stack = []

        signal.signal(signal.SIGCHLD, self.grim_reaper)

    def add_middleware(self, middleware_cls):
        self.middleware_stack.append(middleware_cls)

    def grim_reaper(self, signum, frame):
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except OSError:
                return

            if pid == 0:
                return

    def add_route(self, path, http_method, handler):
        self.routing_table[(path, http_method)] = handler

    def get_handler(self, path, http_method):
        return self.routing_table.get((path, http_method))

    def set_app(self, application):
        self.application = application

    def serve_forever(self):
        listen_socket = self.listen_socket
        while True:
            try:
                client_connection, client_address = listen_socket.accept()
            except IOError as e:
                code, msg = e.args
                # restart 'accept' if it was interrupted
                if code == errno.EINTR:
                    continue
                else:
                    raise

            client_thread = threading.Thread(
                target=self.handle_one_request, args=(client_connection,)
            )
            client_thread.start()

    def handle_one_request(self, client_connection):
        request_data = client_connection.recv(1024).decode("utf-8")
        print("".join(f"< {line}\n" for line in request_data.splitlines()))

        self.parse_request(request_data)

        env = self.get_environ()

        app = self.application
        for middleware_cls in reversed(self.middleware_stack):
            app = middleware_cls(app)

        result = app(env, self.start_response)

        self.finish_response(client_connection, result)

    def parse_request(self, text):
        request_line = text.splitlines()[0]
        request_line = request_line.rstrip("\r\n")
        (self.request_method, self.path, self.request_version) = request_line.split()

    def get_environ(self):
        env = {}
        env["wsgi.version"] = (1, 0)
        env["wsgi.url_scheme"] = "http"
        env["wsgi.input"] = io.StringIO(self.request_data)
        env["wsgi.errors"] = sys.stderr
        env["wsgi.multithread"] = False
        env["wsgi.multiprocess"] = False
        env["wsgi.run_once"] = False
        env["REQUEST_METHOD"] = self.request_method
        env["PATH_INFO"] = self.path
        env["SERVER_NAME"] = self.server_name
        env["SERVER_PORT"] = str(self.server_port)
        return env

    def start_response(self, status, response_headers, exc_info=None):
        server_headers = [
            ("Date", "Mon, 03 Jul 2023 3:54:48 GMT"),
            ("Server", "WSGIServer 0.2"),
        ]
        self.headers_set = [status, response_headers + server_headers]
        # return self.finish_response

    def finish_response(self, client_connection, result):
        try:
            status, response_headers = self.headers_set
            response = f"HTTP/1.1 {status}\r\n"
            for header in response_headers:
                response += "{0}: {1}\r\n".format(*header)
            response += "\r\n"
            for data in result:
                response += data.decode("utf-8")
            print("".join(f"> {line}\n" for line in response.splitlines()))
            response_bytes = response.encode()
            client_connection.sendall(response_bytes)
        finally:
            client_connection.close()


SERVER_ADDRESS = (HOST, PORT) = "", 8888


def make_server(server_address, application):
    server = WSGIServer(server_address)
    server.set_app(application)
    return server


# Define your route handlers (these are example handlers, you should replace them with your actual handlers)
def handle_home(env, start_response):
    start_response("200 OK", [("Content-type", "text/html")])
    return [b"Welcome to the home page!"]


def handle_about(env, start_response):
    start_response("200 OK", [("Content-type", "text/html")])
    return [b"This is the about page."]


def handle_contact(env, start_response):
    start_response("200 OK", [("Content-type", "text/html")])
    return [b"You can contact us here."]


def handle_submit(env, start_response):
    if env["REQUEST_METHOD"] == "POST":
        # Handle form submission here
        start_response("200 OK", [("Content-type", "text/html")])
        return [b"Form submitted successfully!"]
    else:
        start_response("405 Method Not Allowed", [("Content-type", "text/html")])
        return [b"Invalid request method."]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Provide a WSGI application object as module:callable")
    app_path = sys.argv[1]
    module, application = app_path.split(":")
    module = __import__(module)
    application = getattr(module, application)
    httpd = make_server(SERVER_ADDRESS, application)
    httpd.add_route("/", "GET", handle_home)
    httpd.add_route("/about", "GET", handle_about)
    httpd.add_route("/contact", "GET", handle_contact)
    httpd.add_route("/submit", "POST", handle_submit)
    print(f"WSGIServer: Serving HTTP on port {PORT} ...\n")
    httpd.serve_forever()
