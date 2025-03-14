from src import *

# OK 
def get_nf_info(requester_nf_type, token, nf_type=None):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM" 
    uri = f"/nnrf-disc/v1/nf-instances?requester-nf-type={requester_nf_type}"
    if nf_type : uri += f"&target-nf-type={nf_type}"
    return request_cn("NRF", {}, "GET", uri, token=token)

# A TESTER (faut supi donc RAN)
def get_user_data(supi, token):
    # curl "http://127.0.0.3:8000/nudm-dm/v1/imsi-20893${subscriberID}/am-data?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D"
    # https://jdegre.github.io/editor/?url=https://raw.githubusercontent.com/jdegre/5GC_APIs/master/TS29503_Nudm_SDM.yaml
    uri = f"/nudm-sdm/v2/{supi}/am-data"
    return request_cn("UDM", {}, "GET", uri, token=token)

# FIXED
def random_dump(token):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=$randomString&target-nf-type="
    random_string = generate_variables("string")
    return get_nf_info(random_string, token, "")

# FIXED
def crash_nrf(token):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=&target-nf-type="
    return get_nf_info("",token,"")