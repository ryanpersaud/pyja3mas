from scapy.all import *
import socket
# import my_ssl
import ssl
import sys

CERTFILE = "./cert.pem"
KEYFILE = "./key.pem"
# print(my_ssl.HELLO)
# sys.exit(1)

def serv_call(sock, hostname, cb_context):
    # print(sock.recv(1024, socket.MSG_PEEK))
    print(sock)

    print(hostname)
    print(cb_context.__dict__)

def recv(self, buflen=1024, flags=0):
    self._checkClosed()
    if self._sslobj is not None:
        # if flags != 0:
        #     raise ValueError(
        #         "non-zero flags not allowed in calls to recv() on %s" %
        #         self.__class__)
        return self.read(buflen)
    else:
        return super().recv(buflen, flags)

ssl.SSLSocket.recv = recv
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("localhost", 4443))

sock.listen(5)

# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
# context.load_cert_chain(CERTFILE, KEYFILE)
# context.set_servername_callback(serv_call)
# help(context)
# print(context.__dict__)
# ssock = ssl.wrap_socket(sock, certfile=CERTFILE, keyfile=KEYFILE, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)

while True:
    print("Acceptiong new")
    # conn, addr = ssock.accept()
    conn, addr = sock.accept()
    client_hello = conn.recv(2048, socket.MSG_PEEK)
    # print(conn.recv(2048, socket.MSG_PEEK))
    try:
        ssock = ssl.wrap_socket(conn, certfile=CERTFILE, keyfile=KEYFILE, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)
        stuff = ssock.recv(2048)
        # print(ssock.recv(2048, socket.MSG_PEEK))
        # ssock = context.wrap_socket(conn, server_side=True)
        (ip, port) = addr
        print(addr)
    except ssl.SSLError as err:
        print(err)


    try:
        ssock.send(b"HTTP/1.1 200 OK\n"
                +b"Content-Type: text/html\n"
                +b"\n"
                +b"<html><h1>hello</h1></html>")
        # ssock.send(b"<html><h1>hello</h1></html>")
        ssock.shutdown(socket.SHUT_RDWR)
        ssock.close()

    except (OSError, NameError)  as err:
        print(err)
        continue
    
    print("CLIENT HELLO")
    print(client_hello)
    print("STUFF")
    print(stuff)
    print("closed it")
