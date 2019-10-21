# import socket, ssl
import http.server, ssl
from http.client import parse_headers
import httpagentparser

HOST = "localhost"
PORT = 4443

KEYFILE = "key.pem"
CERTFILE = "cert.pem"

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers["User-Agent"]

        print(httpagentparser.detect(ua))
        

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'hello world!')


def main():
    server_addr = (HOST, PORT)
    httpd = http.server.HTTPServer(server_addr, SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile=CERTFILE, keyfile=KEYFILE, ssl_version=ssl.PROTOCOL_TLSv1_2)
    httpd.serve_forever()


if __name__ == '__main__':
  main()
