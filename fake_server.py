from scapy.all import *
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("localhost", 4443))

sock.listen(5)

while True:
    conn, addr = sock.accept()
    (ip, port) = addr
    print(addr)
    # ss = StreamSocket(conn)
    ss = SimpleSocket(conn)
    # print(ss.__dict__["basecls"])
    print(ss.recv_raw())
    print("_---------------------------------")

    fin_pkt = IP(dst=ip)/TCP(dport=port, flags="F")
    # fin_pkt = IP(dst=ip, src="127.0.0.69")/TCP(sport=4443, dport=port)/fuzz(Raw())
    print(fin_pkt)

    print("_---------------------------------")
    # FINACK = ss.sr1(fin_pkt)
    ss.send(fin_pkt)
    FINACK = ss.recv()
    print(FINACK)

    # ss.send(fin_pkt)
    ss.close()

# raw_pkt = sniff(iface="lo0", filter="tcp port 4443", count=1)
# raw_pkt = raw_pkt[0]
# print(raw_pkt)
