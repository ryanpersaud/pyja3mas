import http.server, ssl
from http.client import parse_headers
import httpagentparser
import re
import logging
import logging.config
import time

import Sniffer
import log_conf

HOST = "localhost"
PORT = 4443

KEYFILE = "key.pem"
CERTFILE = "cert.pem"

_LOGGER = None
_SHARED_JA3 = None

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    curl_re = r"(curl\/(\d+\.)?(\d+\.)?(\d+))"

    def do_GET(self):
        _LOGGER.info(self.client_address)
        _LOGGER.debug("Got GET Req")
        ua = self.headers["User-Agent"]

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

        
        browser_info = (browser_name, browser_version)
        _LOGGER.info(browser_info)

        self.send_response(200)
        self.end_headers()

        ja3 = None
        time_wasted = 0
        unique_key = self.client_address
        while ja3 is None and time_wasted < 5:
            time.sleep(0.5)
            ja3 = _SHARED_JA3.get(unique_key, None)
            time_wasted += 1

        if ja3 is not None:
            ja3 = ja3["ja3_digest"]

        ret_bytes = ("Browser: %s\n" \
                "Version: %s\n" \
                "JA3: %s" % (browser_info[0], browser_info[1], ja3)).encode("utf-8")
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


def main():
    init_logger()

    global _SHARED_JA3
    _SHARED_JA3 = {}

    server_addr = (HOST, PORT)
    httpd = http.server.HTTPServer(server_addr, SimpleHTTPRequestHandler)

    _LOGGER.debug("Wrapping HTTP socket in SSL wrapper")
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, \
            certfile=CERTFILE, keyfile=KEYFILE, \
            ssl_version=ssl.PROTOCOL_TLSv1_2)
    

    sniffer = Sniffer.Sniffer(_LOGGER, shared_ja3=_SHARED_JA3)
    sniffer.start()

    try:
        _LOGGER.info("Launching HTTPS Server")
        httpd.serve_forever()
    except KeyboardInterrupt as _:
        _LOGGER.info("Tearing Down Server and Sniffer")
        sniffer.join(0.2)

    _LOGGER.info(sniffer.get_ja3_dict())


if __name__ == '__main__':
  main()
