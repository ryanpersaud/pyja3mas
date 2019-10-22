from scapy.all import *
from threading import Thread, Event

import ja3

class Sniffer(Thread):
    def __init__(self, logger, shared_ja3={}, interface="lo0"):
        super().__init__()

        self.interface = interface
        self.stop_sniffer = Event()
        self.logger = logger

        self.logger.debug("Created Sniffer Object")

        self._ja3 = shared_ja3

        self.daemon = True

    def run(self):
        self.logger.info("Starting sniffer on interface: %s", self.interface)

        sniff(iface=self.interface, prn=ja3.ssl_closure(self._ja3, self.logger), \
                filter="tcp port 4443", stop_filter=self.should_stop_sniffer)

    def join(self, timeout=None):
        self.logger.debug("Joining the sniffer")
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def get_ja3_dict(self):
        return self._ja3
