import http.server, ssl
from http.client import parse_headers
import httpagentparser
import re
import logging
import logging.config
from pprint import pformat
import json
import os
import time
import sys
import socket

import Sniffer
import log_conf

HOST = "localhost"
PORT = 4443

KEYFILE = "key.pem"
CERTFILE = "cert.pem"

JA3_FILE = "ja3_data.json"

_LOGGER = None
_SHARED_JA3 = None
_MASTER_JA3 = None

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    curl_re = r"(curl\/(\d+\.)?(\d+\.)?(\d+))"

    def do_GET(self):
        _LOGGER.debug("Got GET Req from: %s", self.client_address)
        ua = self.headers["User-Agent"]
        print(ua)

        found_curl = SimpleHTTPRequestHandler.check_for_curl(ua)
        browser_name = None
        browser_version = None

        if found_curl is not None:
            _LOGGER.debug("Detected Curl")
            # can split because it passed the regex
            curl_info = found_curl.split("/")
            browser_name = "curl"
            browser_version = curl_info[1]

        else:
            parsed_ua = httpagentparser.detect(ua)
            browser = parsed_ua.get("browser", None)
            if parsed_ua.get("browser", None) is not None:
                browser_name = parsed_ua["browser"].get("name", None)
                browser_version = parsed_ua["browser"].get("version", None)


        browser_info = (browser_name, browser_version, ua)

        self.send_response(200)
        self.end_headers()

        ja3 = None
        time_wasted = 0
        unique_key = self.client_address

        # designed to wait a couple seconds if there is a connection issue if
        # the sniffer didn't add the ja3 data
        while ja3 is None and time_wasted < 5:
            time.sleep(0.3)
            ja3 = _SHARED_JA3.get(unique_key, None)
            time_wasted += 1

        if ja3 is not None:
            ja3 = ja3["ja3_digest"]

        ret_bytes = ("Browser: %s\n" \
                "Version: %s\n" \
                "JA3: %s" % (browser_info[0], browser_info[1], ja3)).encode("utf-8")

        _LOGGER.info("Digested Connection from: %s::%s::%s", browser_name, browser_version, ja3)

        # adds any new data to a dictionary
        if _MASTER_JA3.get(ja3, None) is None:
            _MASTER_JA3[ja3] = []

        if browser_info not in _MASTER_JA3[ja3]:
            _MASTER_JA3[ja3].append(browser_info)

        self.wfile.write(ret_bytes)


    def log_message(self, format, *args):
        return


    @staticmethod
    def check_for_curl(ua_str):
        matchObj = re.search(SimpleHTTPRequestHandler.curl_re, ua_str)
        if matchObj is not None:
            return matchObj.group()

        return None


def init_logger():
    global _LOGGER

    logging.config.dictConfig(log_conf.LOGGING_CONFIG)
    _LOGGER = logging.getLogger("info")

def add_to_ds():
    # default make it the master dict that will get overwritten if the data
    # file exists
    curr_ja3 = _MASTER_JA3

    # file exists, so read it in and do stuffs
    if os.path.exists(JA3_FILE):
        _LOGGER.info("Reading in current JA3 data")

        # test that the json file is set up correctly
        try:
            with open(JA3_FILE, "r") as ja_f:
                curr_ja3 = json.loads(ja_f.read())

            curr_ja3.get("testing", None)

            for ja3 in _MASTER_JA3:
                browsers = _MASTER_JA3[ja3]
                for brow in browsers:
                    # the ja3 is completely new
                    if curr_ja3.get(ja3, None) is None:
                        _LOGGER.info("New JA3 Detected")
                        # create the ja3 entry and add current brow
                        curr_ja3[ja3] = [brow]
                    # the ja3 exists but the browser entry is not in the data store
                    elif brow not in curr_ja3[ja3]:
                        # add to the list of known browsers with the JA3 hash
                        curr_ja3[ja3].append(brow)

                    # do nothing because the JA3 exists and the current browser
                    # already exists too
        except (AttributeError, json.decoder.JSONDecodeError) as exc:
            _LOGGER.error("Data Store JSON not configured correctly")
            _LOGGER.error("Overriding misconfigured JSON data store with " \
                    "current master JA3 list")


    # rewrite the dictionary to the file
    _LOGGER.info("Adding new JA3 fingerprints to the data store")
    json_curr_ja3 = json.dumps(curr_ja3)
    with open(JA3_FILE, "w") as ja_f:
        ja_f.write(json_curr_ja3)


def main():
    init_logger()

    global _SHARED_JA3
    global _MASTER_JA3
    _SHARED_JA3 = {}
    _MASTER_JA3 = {}

    server_addr = (HOST, PORT)
    httpd = http.server.HTTPServer(server_addr, SimpleHTTPRequestHandler)

    _LOGGER.debug("Wrapping HTTP socket in SSL wrapper")
    # print(httpd.socket)
    # conn, addr = httpd.socket.accept()
    # print(conn.recv(1024, socket.MSG_PEEK))
    # httpd.socket = ssl.wrap_socket(conn, server_side=True, \
    #         certfile=CERTFILE, keyfile=KEYFILE, \
    #         ssl_version=ssl.PROTOCOL_TLSv1_2)

    # print(httpd.socket.recv(2048, socket.MSG_PEEK))


    sniffer = Sniffer.Sniffer(_LOGGER, shared_ja3=_SHARED_JA3)
    sniffer.start()

    try:
        _LOGGER.info("Launching HTTPS Server")
        httpd.serve_forever()
    except KeyboardInterrupt as _:
        _LOGGER.info("Tearing Down Server and Sniffer")
        sniffer.join(0.1)

    _LOGGER.info("Current JA3 Results...")
    _LOGGER.info(pformat(_MASTER_JA3))

    add_to_ds()


if __name__ == '__main__':
    main()
