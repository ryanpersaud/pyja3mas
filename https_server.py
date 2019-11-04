"""HTTPS server for collecting JA3 Fingerprints.

This script stands up a simple working HTTPS server that users can connnect to
and create a TLS connection.

It currently requires valid certificates to become a reputable and trusted
HTTPS server.
"""

import argparse
import logging
import logging.config
from pprint import pformat
import re
import socket
import ssl
import sys
import select
import time

import queue
import httpagentparser

import log_conf
import ja3
import dynamodb_access as ddb

_DYNAMO_ACCESS = None
"""DynamoDBAccess Obj: Global private module variable to store the connection
object to the DynamoDB table in AWS """

DB_TABLE_NAME = "JA3Fingerprints"
"""str Obj: table name in AWS to connect to"""
DB_PRIM_KEY_NAME = "ja3"
"""str Obj: primary key to use for accessing and updating the DynamoDB table"""
VALUE_NAME = "browserinfo"
"""str Obj: value name of the KV pair in the DynamoDB table"""

CERTFILE = "./certs/fullchain.pem"
"""str Obj: file path to the certificate PEM file"""
KEYFILE = "./certs/privkey.pem"
"""str Obj: file path to the private key PEM file"""

HOST = ""
"""str Obj: hostname to bind to"""
PORT = 4443
"""int: port number where the https server will be accepting connections"""

_LOGGER = None
"""Logger Obj: Global private module variable to store the logger for the program"""

CURL_RE = r"(curl\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting cURL data"""
WGET_RE = r"([wW]get\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting wget data"""
REQUESTS_RE = r"(python-requests\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting python-requests data"""

EXIT_SUCC = 0
PARAM_ERROR = 1
CONFIG_ERROR = 2
"""int: module variables for return codes"""


# def check_for_curl(request):
def check_for_headless_browsers(request):
    """Given a UA string, determines if the request came from cURL
    
    Args:
        request (:obj: `str`) UA string or full HTTP request to parse for cURL

    Returns:
        (:obj: `re`) regex object that is parseable if a match for cURL is
            found, None otherwise
    """

    # performs the regex matching
    # starts with curl
    match_obj = re.search(CURL_RE, request)
    # if not curl, then tries wget
    if match_obj is None:
        match_obj = re.search(WGET_RE, request)
    # if not wget, then tries requests module
    if match_obj is None:
        match_obj = re.search(REQUESTS_RE, request)

    if match_obj is not None:
        return match_obj.group()

    return None


def extract_ua_str(request):
    _LOGGER.debug("Attempting to Extract User-Agent String")

    ua_idx = request.find(b"User-Agent")
    new_substr = request[ua_idx + len("User-Agent: "):]
    end_ua_idx = new_substr.find(b"\r\n")
    ua_str = new_substr[:end_ua_idx]

    return ua_str


def setup_arguments(parser):
    parser.add_argument("--debug", help="Turn on debug logging",
                        action="store_true")


def init_logger(debug_on):
    global _LOGGER

    # prod-level stdout
    log_conf.LOGGING_CONFIG["handlers"]["consoleHandler"]["formatter"] = "fileFormatter"

    logging.config.dictConfig(log_conf.LOGGING_CONFIG)

    if debug_on:
        _LOGGER = logging.getLogger("debug")
    else:
        _LOGGER = logging.getLogger("info")
    _LOGGER.info("Logger created")
    _LOGGER.debug("Debug On")


def init_dynamo_access():
    global _DYNAMO_ACCESS

    try:
        _DYNAMO_ACCESS = ddb.DynamoDBAccess(DB_TABLE_NAME, DB_PRIM_KEY_NAME)
    except (ddb.TableDoesNotExistException, ddb.PrimKeyException) as err:
        _LOGGER.critical(err)
        _LOGGER.critical("Cannot connect to Dynamo Database...Exiting")
        sys.exit(CONFIG_ERROR)

    _LOGGER.info("Connected to Dynamo DB Table '%s'", DB_TABLE_NAME)


def main():
    parser = argparse.ArgumentParser()
    setup_arguments(parser)
    args = parser.parse_args()

    init_logger(args.debug)
    init_dynamo_access()

    READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
    READ_WRITE = READ_ONLY | select.POLLOUT
    TIMEOUT = 1000


    _LOGGER.debug("Initializing Socket")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)

    message_queues = {}

    poller = select.poll()
    poller.register(sock)

    fd_to_socket = {sock.fileno(): sock,}
    sock_to_ja3 = {}

    _LOGGER.info("Launching Server on https://ja3.appianis.com:%d", PORT)

    while True:
        events = poller.poll(TIMEOUT)

        for fd, flag in events:
            s = fd_to_socket[fd]

            if flag & (select.POLLIN | select.POLLPRI):
                # server socket gets a new connection
                if s is sock:
                    conn, addr = sock.accept()
                    _LOGGER.debug("New TCP Connection Created: %s", addr)

                    try:
                        # peek and get the client HELLO for the TLS handshake
                        client_hello = conn.recv(2048, socket.MSG_PEEK)

                        # we got data from it and it didn't hangup
                        if client_hello:
                            ja3_record = ja3.process_ssl(client_hello)
                            # handles if the client_hello is not TLS handshake or just plain HTTP
                            if ja3_record is not None:
                                ja3_digest = ja3_record.get("ja3_digest", None)

                            # complete the TLS handshake
                                ssock = ssl.wrap_socket(conn, certfile=CERTFILE, \
                                        keyfile=KEYFILE, server_side=True, \
                                        ssl_version=ssl.PROTOCOL_TLSv1_2)

                                # add the socket for later use
                                fd_to_socket[ssock.fileno()] = ssock
                                # add the ja3 digest to the socket
                                sock_to_ja3[ssock] = ja3_digest

                                poller.register(ssock, READ_ONLY)
                                message_queues[ssock] = queue.Queue()

                                _LOGGER.info("New TLS Connection Established: %s", addr)
                                _LOGGER.info("JA3: (%s,%s) :: %s", addr[0], addr[1], ja3_digest)

                            else:
                                _LOGGER.info("Closing connection...Invalid HTTPS "
                                             "connection from: %s", addr)
                                conn.shutdown(socket.SHUT_RDWR)
                                time.sleep(1)
                                conn.close()
                        else:
                            _LOGGER.info("Client %s Hung Up before initiating TLS Handshake", addr)

                    except ssl.SSLError as err:
                        _LOGGER.debug(err)

                # not init connection to the server
                else:
                    # hopefully get the GET request here for UA string processing
                    init_request = s.recv(2048)

                    if init_request:
                        try:
                            _LOGGER.debug(init_request)
                            # it's a GET request
                            if b"GET" in init_request:
                                ua_str = extract_ua_str(init_request)

                                # real quick check for curl browser
                                # found_headless = check_for_curl(ua_str.decode("utf-8"))
                                found_headless = check_for_headless_browsers(ua_str.decode("utf-8"))
                                browser_name = "Unknown"
                                browser_version = "Unknown"

                                if found_headless is not None:
                                    _LOGGER.debug("Detected headless")
                                    headless_info = found_headless.split("/")
                                    browser_name = headless_info[0]
                                    browser_version = headless_info[1]

                                else:
                                    # need to decode utf-8 because the agent
                                    # parser requires a str input
                                    parsed_ua = httpagentparser.detect(ua_str.decode("utf-8"))
                                    browser = parsed_ua.get("browser", None)
                                    if browser is not None:
                                        browser_name = parsed_ua["browser"].get("name", None)
                                        browser_version = parsed_ua["browser"].get("version", None)

                                # grab the ja3 associated with the socket
                                ja3_digest = sock_to_ja3[s]
                                browser_info = [ja3_digest, browser_name, \
                                        browser_version, \
                                        ua_str.decode("utf-8")]
                                _LOGGER.info(browser_info)

                                # adds to the dynamo db instance
                                _LOGGER.info("Writing Browser info to Database")
                                # browser info is everything but the JA3 hash
                                # above that is logged
                                browser_db_info = browser_info[1:]

                                _DYNAMO_ACCESS.add_to_table(ja3_digest, \
                                        VALUE_NAME, browser_db_info)

                                # real quick edge case if we can't parse the UA
                                # string properly, it won't crash the server
                                b_name = b""
                                b_version = b""

                                if browser_name is not None:
                                    b_name = browser_name.encode("utf-8")
                                if browser_version is not None:
                                    b_version = browser_version.encode("utf-8")

                                reply = b"HTTP/1.1 200 OK\n" \
                                        +b"Content-Type: text/html\n" \
                                        +b"\n" \
                                        +b"<html><h1>%b</h1><h1>%b</h1><h1>%b</h1></html>" % \
                                        (ja3_digest.encode("utf-8"), b_name, b_version)
                                # add the message reply to the queue
                                message_queues[s].put(reply)
                                poller.modify(s, READ_WRITE)

                        except (OSError, NameError)  as err:
                            # this needs to be debug because these errors are
                            # always expected to happen
                            # don't want this printing out every time
                            _LOGGER.debug(err)
                            continue

                    else:
                        poller.unregister(s)
                        s.shutdown(socket.SHUT_RDWR)
                        time.sleep(1)
                        s.close()

                        del message_queues[s]
                        del sock_to_ja3[s]

                    _LOGGER.debug(pformat(ja3_record))

            # client hangs up
            elif flag & select.POLLHUP:
                # close everything
                poller.unregister(s)
                s.shutdown(socket.SHUT_RDWR)
                time.sleep(1)
                s.close()

            # we have output to send to the client
            elif flag & select.POLLOUT:
                try:
                    next_msg = message_queues[s].get_nowait()
                # we've got nothing to send it
                except queue.Empty:
                    poller.modify(s, READ_ONLY)

                else:
                    # respond with the message
                    s.send(next_msg)
                    poller.unregister(s)
                    # close it because we got what we needed
                    s.shutdown(socket.SHUT_RDWR)
                    time.sleep(1)
                    s.close()

                    del message_queues[s]
                    del sock_to_ja3[s]

            # little error happened
            elif flag & select.POLLERR:
                # close everything
                poller.unregister(s)
                s.shutdown(socket.SHUT_RDWR)
                time.sleep(1)
                s.close()

                del message_queues[s]
                del sock_to_ja3[s]


if __name__ == "__main__":
    main()
    sys.exit(EXIT_SUCC)
