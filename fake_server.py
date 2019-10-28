# from scapy.all import *
import httpagentparser
import logging
import logging.config
from pprint import pformat
import re
import socket
import ssl
import sys

import log_conf
import ja3

CERTFILE = "./cert.pem"
KEYFILE = "./key.pem"

HOST = "localhost"
PORT = 4443

_LOGGER = None

CURL_RE = r"(curl\/(\d+\.)?(\d+\.)?(\d+))"

def check_for_curl(ua_str):
    pass

def extract_ua_str(request):
    pass

def init_logger():
    global _LOGGER

    logging.config.dictConfig(log_conf.LOGGING_CONFIG)
    _LOGGER = logging.getLogger("info")

def main():
    init_logger()

    _LOGGER.debug("Initializing Socket")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)

    _LOGGER.debug("Launching Server")

    while True:
        conn, addr = sock.accept()
        client_hello = conn.recv(2048, socket.MSG_PEEK)
        ja3_record = ja3.process_ssl(client_hello)
        ja3_digest = ja3_record.get("ja3_digest", None)

        try:
            ssock = ssl.wrap_socket(conn, certfile=CERTFILE, keyfile=KEYFILE, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)
            init_request = ssock.recv(2048)
            (ip, port) = addr
            _LOGGER.info("New TLS Connection Established: %s", addr)
            _LOGGER.info("JA3: %s", ja3_digest)
            
        except ssl.SSLError as err:
            # this needs to be debug because these errors are always expected to happen
            # don't want this printing out every time
            _LOGGER.debug(err)


        try:
            if b"GET" in init_request:
                ua_idx = init_request.find(b"User-Agent")
                new_substr = init_request[ua_idx + len("User-Agent: "):]
                end_ua_idx = new_substr.find(b"\r\n")
                ua_str = new_substr[:end_ua_idx]

                # need to decode utf-8 because the agent parser requires a str input
                parsed_ua = httpagentparser.detect(ua_str.decode("utf-8"))
                # _LOGGER.info(parsed_ua)
                browser_name = None
                browser_version = None
                browser = parsed_ua.get("browser", None)
                if browser is not None:
                    browser_name = parsed_ua["browser"].get("name", None)
                    browser_version = parsed_ua["browser"].get("version", None)


                browser_info = (ja3_digest, browser_name, browser_version, ua_str.decode("utf-8"))
                _LOGGER.info(browser_info)

                _LOGGER.info("Replying to GET Req: %s", addr)
                ssock.send(b"HTTP/1.1 200 OK\n"
                        +b"Content-Type: text/html\n"
                        +b"\n"
                        +b"<html><h1>%b</h1><h1>%b</h1><h1>%b</h1></html>" % \
                        (ja3_digest.encode("utf-8"), browser_name.encode("utf-8"), \
                            browser_version.encode("utf-8")))


            ssock.shutdown(socket.SHUT_RDWR)
            ssock.close()

            _LOGGER.debug("Shutting down connection with: %s", addr)

        except (OSError, NameError)  as err:
            # this needs to be debug because these errors are always expected to happen
            # don't want this printing out every time
            _LOGGER.debug(err)
            continue
        

        _LOGGER.debug(pformat(ja3_record))



if __name__ == "__main__":
    main()
