from src import *
import json

# OK
def get_am_data(supi, token, mcc, mnc, display=True):
    # curl "http://127.0.0.3:8000/nudm-dm/v1/imsi-20893${subscriberID}/am-data?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D"
    # https://jdegre.github.io/editor/?url=https://raw.githubusercontent.com/jdegre/5GC_APIs/master/TS29503_Nudm_SDM.yaml
    

    # urls = [
    #     "/nudr-dr/v2/subscription-data/imsi-208930000000001/20893/provisioned-data/am-data?supported-features=%7B%22mcc%22%3A+%22208%22%2C+%22mnc%22%3A+%2293%22%7D",
    #     "/nudm-sdm/v2/imsi-208930000000001/sm-data?plmn-id=%7B%22mcc%22%3A+208%2C+%22mnc%22%3A+93%7D",
    #     "/nudm-sdm/v2/imsi-208930000000001",
    #     "/nudr-dr/v2/subscription-data/imsi-208930000000001/authentication-data/authentication-subscription",
    #     "/nudm-sdm/v2/imsi-208930000000001/nssai?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D",
    #     "/nudm-sdm/v2/imsi-208930000000001/smf-select-data?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D",
    #     "/nudm-sdm/v2/imsi-208930000000001/ue-context-in-smf-data"
    #     "/nudr-dr/v2/subscription-data/imsi-208930000000001/context-data/smf-registrations?supported-features=",
    #     "/nudr-dr/v2/policy-data/ues/imsi-208930000000001/am-data",
    #     "/nudm-sdm/v2/imsi-208930000000001/sm-data?dnn=internet&plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D&single-nssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22010203%22%7D", 
    #     "/nudr-dr/v2/application-data/influenceData?dnns=internet&snssais=%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22112233%22%7D%5D&supis=imsi-208930000000001"
        
    # ]
    # for url in urls:
    #     request_cn("UDM", {}, "GET", url, token=token, display=display)
    # return

    uri  = f"/nudm-sdm/v2/{supi}/am-data"
    data = {"plmn-id": json.dumps({"mcc": mcc, "mnc": mnc})}
    return request_cn("UDM", data, "GET", uri, token=token, display=display)

# OK
def get_dnn(supi, token, mcc, mnc, display=True):
    #  "/nudm-sdm/v2/imsi-208930000000001/smf-select-data?plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D",
    uri  = f"/nudm-sdm/v2/{supi}/smf-select-data"
    data = {"plmn-id": json.dumps({"mcc": mcc, "mnc": mnc})}
    return request_cn("UDM", data, "GET", uri, token=token, display=display)

# OK
def get_sm_data(supi, token, mcc, mnc, sst, sd, display=True):
    # "/nudm-sdm/v2/imsi-208930000000001/sm-data?dnn=internet&plmn-id=%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D&single-nssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22010203%22%7D", 
    uri  = f"/nudm-sdm/v2/{supi}/sm-data"
    data = {
        "dnn": "internet",
        "plmn-id": json.dumps({"mcc": mcc, "mnc": mnc}),
        "single-nssai": json.dumps({"sst": sst, "sd": sd})
    }
    return request_cn("UDM", data, "GET", uri, token=token, display=display)