from src import *

def test_manipulation():
    """
        CN neeed to be up and running
        One UE need to be registered with supi = imsi-208930000000001
        MITM need to be setup on EVIL else you'll get "ConnectError: [Errno 111] Connection refused"
    """
    
    ip     = f"http://{ip_list['EVIL']}:8000/" # MITM iP
    supi   = "imsi-208930000000001"
    mcc    = "208"
    mnc    = "93"
    uri    = f"nudm-sdm/v2/{supi}/smf-select-data"
    data   = {"plmn-id": json.dumps({"mcc": mcc, "mnc": mnc})}
    method = "GET"
    
    print("If you see this and have \"ConnectError: [Errno 111] Connection refused\", verify that your MITM is setup on the EVIL machine")
    code, _ = victim_request(ip,uri,data,method)
    assert 200 <= code < 300
        
