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
import os
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
POWERSHELL_RE = r"([pP]ower[sS]hell\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting PowerShell data"""
GO_RE = r"([gG]o\D+\/(\d\.)?(\d\.)?(\d+))"
"""str Obj: regex string specifically for extracting Go data"""

LOG_FNAME = "server.log"
LOG_DIR = "logs"

EXIT_SUCC = 0
PARAM_ERROR = 1
CONFIG_ERROR = 2
"""int: module variables for return codes"""

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
READ_WRITE = READ_ONLY | select.POLLOUT
TIMEOUT = 1000

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
    # if not requests, then tries powershell
    if match_obj is None:
        match_obj = re.search(POWERSHELL_RE, request)
    # if not powershell, then tries Go
    if match_obj is None:
        match_obj = re.search(GO_RE, request)

    if match_obj is not None:
        return match_obj.group()

    return None


def extract_ua_str(request):
    """Attempts to extract a User-Agent string from an HTTP GET request.

    If the GET request contains a User-Agent string, it will extract just the
    UA string.

    Args:
        request (:obj: `str`) full HTTP GET Request

    Returns:
        (:obj: `bytes`) the UA string, or 'Unknown' if it is not found
    """

    _LOGGER.debug("Attempting to Extract User-Agent String")
    # _LOGGER.info(request)

    ua_idx = request.find(b"User-Agent")
    if ua_idx >= 0:
        new_substr = request[ua_idx + len("User-Agent: "):]
        end_ua_idx = new_substr.find(b"\r\n")
        # returns the UA string if found
        return new_substr[:end_ua_idx]

    # returns empty if no UA string
    return b"Unknown"


def setup_arguments(parser):
    """Sets up command line arguments

    Args:
        parser (:obj: `ArgParse`) parser object to add arguments to

    Returns:
        void
    """

    parser.add_argument("--debug", help="Turn on debug logging",
                        action="store_true")


def init_logger(debug_on):
    """Initializes the private module variable logger

    Adds the file formatter and logging file to the default logging
    configuration.

    Args:
        debug_on (bool): boolean determining if debug mode is set via the
            command line

    Returns:
        void
    """

    global _LOGGER

    # prod-level stdout
    log_conf.LOGGING_CONFIG["handlers"]["consoleHandler"]["formatter"] = "fileFormatter"
    log_conf.LOGGING_CONFIG["handlers"]["fileHandler"]["filename"] = "%s/%s" % (LOG_DIR, LOG_FNAME)

    if not os.path.isdir(LOG_DIR):
        os.mkdir(LOG_DIR)

    logging.config.dictConfig(log_conf.LOGGING_CONFIG)

    if debug_on:
        _LOGGER = logging.getLogger("debug")
    else:
        _LOGGER = logging.getLogger("user")
    _LOGGER.info("Logger created")
    _LOGGER.debug("Debug On")


def init_dynamo_access():
    """Initializes the DynamoDB private module variable to access the AWS
    DynamoDB instance that will store the JA3 fingerprints.

    Args:
        void

    Returns:
        void
    """

    global _DYNAMO_ACCESS

    try:
        # create dyanmo object
        _DYNAMO_ACCESS = ddb.DynamoDBAccess(DB_TABLE_NAME, DB_PRIM_KEY_NAME)
    except (ddb.TableDoesNotExistException, ddb.PrimKeyException) as err:
        # any exception means it could not successfully connect ot the dynamo
        # table
        _LOGGER.critical(err)
        _LOGGER.critical("Cannot connect to Dynamo Database...Exiting")
        sys.exit(CONFIG_ERROR)

    _LOGGER.info("Connected to Dynamo DB Table '%s'", DB_TABLE_NAME)


def handle_new_conn(sock, fd_to_socket, message_queues, poller):
    conn, addr = sock.accept()
    conn.setblocking(0)
    fd_to_socket[conn.fileno()] = conn
    poller.register(conn, READ_ONLY)
    _LOGGER.debug("New TCP Connection Created: %s", addr)


def retrieve_http_req(s, message_queues, sock_to_ja3, poller):
    # hopefully get the GET request here for UA string processing
    try:
        init_request = s.recv(2048)
    except BlockingIOError as err:
        _LOGGER.error("Nothing to read")
        return False

    except ConnectionResetError as err:
        _LOGGER.error("Connection reset: %s", err)
        return False

    # _LOGGER.error(init_request)
    # data exists from the previous read
    if init_request:
        try:
            # it's a GET request
            if b"GET" in init_request:
                _LOGGER.debug(init_request)
                ua_str = extract_ua_str(init_request)
                browser_name = "Unknown"
                browser_version = "Unknown"

                # it could extract the UA section of the header
                if ua_str != b"Unknown":
                    # real quick check for any headless browser(s)
                    found_headless = \
                        check_for_headless_browsers(ua_str.decode("utf-8"))

                    # it got a hit from a headless browser
                    if found_headless is not None:
                        _LOGGER.debug("Detected headless")
                        # splits and extracts name/version
                        headless_info = found_headless.split("/")
                        browser_name = headless_info[0]
                        browser_version = headless_info[1]

                    else:
                        # need to decode utf-8 because the agent
                        # parser requires a str input
                        parsed_ua = httpagentparser.detect(ua_str.decode("utf-8"))
                        browser = parsed_ua.get("browser", None)
                        # the UA parser was able to
                        # successfully extract a browser
                        if browser is not None:
                            browser_name = parsed_ua["browser"].get("name", None)
                            browser_version = \
                                parsed_ua["browser"].get("version", None)

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

                # makes an external call to add the JA3 to the
                # table with the appropriate browser information
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
                # tell the poller we ready to send it
                poller.modify(s, READ_WRITE)

                return True

        except (OSError, NameError)  as err:
            # this needs to be warning because these errors are
            # always expected to happen
            # don't want this printing out every time
            _LOGGER.warning(err)
            return False

    else:
        _LOGGER.warning("nothing read")
        return False

    _LOGGER.debug(pformat(ja3_record))


def tls_handshake(sock, message_queues, fd_to_socket, sock_to_ja3, poller):
    try:
        # peek and get the client HELLO for the TLS handshake
        _LOGGER.info(type(sock))
        # we have an ssl socket, then we've already completed the TLS handshake
        if isinstance(sock, ssl.SSLSocket):
            _LOGGER.info("returning the sssl socket for falso")
            return False

        # otherwise, we peek at the TLS handshake
        _LOGGER.info("receiving client hello")
        client_hello = sock.recv(2048, socket.MSG_PEEK)
        _LOGGER.info("HELLO: %s", client_hello)

        addr = sock.getpeername()

        # we got data from it and it didn't hangup
        if client_hello:
            ja3_record = ja3.process_ssl(client_hello)
            # handles if the client_hello is not TLS handshake or just plain HTTP
            if ja3_record is not None:
                ja3_digest = ja3_record.get("ja3_digest", None)

                # gets rid of the non-ssl socket
                del fd_to_socket[sock.fileno()]
                poller.unregister(sock)

                # need to set to blocking for a hot sec so it can complete the TLS handshake
                sock.setblocking(1)

                # complete the TLS handshake by wrapping the
                # socket in the ssl module
                _LOGGER.debug("Attempting to wrap the socket with SSL")

                try:
                    ssock = ssl.wrap_socket(sock, certfile=CERTFILE, \
                            keyfile=KEYFILE, server_side=True, \
                            ssl_version=ssl.PROTOCOL_TLSv1_2)
                except Exception as err:
                    _LOGGER.error(err)
                    _LOGGER.error("Something went wrong")
                    return


                _LOGGER.info("got peername")
                # set the ssl socket to be nonblocking
                ssock.setblocking(0)
                _LOGGER.debug("created TLS connection, adding SSL socket to poller")

                # add the ssl socket for later use
                fd_to_socket[ssock.fileno()] = ssock
                # add the ja3 digest to the socket
                sock_to_ja3[ssock] = ja3_digest

                # it's a new ssl socket client, so register the poller to
                # look out for it
                poller.register(ssock, READ_ONLY)
                message_queues[ssock] = queue.Queue()

                _LOGGER.info("New TLS Connection Established: %s", addr)
                _LOGGER.info("JA3: (%s,%s) :: %s", addr[0], addr[1], ja3_digest)

                # successful TLS handshake
                return True

            else:
                # _LOGGER.info("Closing connection...Invalid HTTPS "
                #              "connection from: %s", addr)

                _LOGGER.debug("Did not receive TLS handshake from %s", addr)

                # no message queue yet or ja3 digest
                return False

        else:
            _LOGGER.info("Client %s Hung Up before initiating TLS Handshake", addr)
            _LOGGER.debug(sock)
            cleanup_connection(sock, poller)
            return None

    except BlockingIOError as err:
        _LOGGER.warning("Blocking IO Err: %s", err)
        return False

    except ssl.SSLError as err:
        _LOGGER.warning("SSL Err: %s", err)

    except OSError as err:
        _LOGGER.info("HELLO")
        time.sleep(3)
        _LOGGER.warning(err)
        _LOGGER.warning(sock.fileno())
        return None



def cleanup_connection(sock, poller, message_queues=None, sock_to_ja3=None):
    try:
        _LOGGER.info("Closing connection to %s", sock.getpeername())
    except OSError as err:
        _LOGGER.error(err)
        _LOGGER.info("Closing connection to %s", sock)

    poller.unregister(sock)
    # gracefully shutdown to eliminate RST packets
    sock.close()

    if message_queues is not None:
        del message_queues[sock]
    if sock_to_ja3 is not None:
        del sock_to_ja3[sock]


def main():
    """Main method that runs and handles the HTTPs server concurrently

    Args:
        void

    Returns:
        void
    """

    parser = argparse.ArgumentParser()
    setup_arguments(parser)
    args = parser.parse_args()

    init_logger(args.debug)
    init_dynamo_access()

    _LOGGER.debug("Initializing Socket")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    sock.bind((HOST, PORT))
    sock.listen(11)

    # queue for sending messages back to the clients
    message_queues = {}

    poller = select.poll()
    poller.register(sock, READ_ONLY)

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
                    handle_new_conn(s, fd_to_socket, message_queues, poller)

                # not init connection to the server
                else:
                    # checks if this is the second event fired and need to grab the TLS handshake
                    handshake = tls_handshake(s, message_queues, fd_to_socket, sock_to_ja3, poller)
                    # checks either error or non tls handshake
                    if handshake is not None and not handshake:
                        # check if there is an HTTP GET request because
                        # tls_handshake returned False
                        if not retrieve_http_req(s, message_queues, sock_to_ja3, poller):
                            # we didn't get a GET, so close it
                            _LOGGER.error(type(s))
                            cleanup_connection(s, poller, message_queues, sock_to_ja3)

            # client hangs up
            elif flag & select.POLLHUP:
                cleanup_connection(s, poller)

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
                    # we do not keep any more connections after we use the client
                    # for the JA3 fingerprint
                    cleanup_connection(s, poller, message_queues, sock_to_ja3)

            # little error happened
            elif flag & select.POLLERR:
                # close everything
                cleanup_connection(s, poller, message_queues, sock_to_ja3)


if __name__ == "__main__":
    main()
    sys.exit(EXIT_SUCC)
