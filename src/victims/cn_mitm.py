
import httpx
from src import *
import json

def victim_request(ip, uri, data, method):
    
    # Create legitimate AMF to test the MITM 
    nf_instance_id = generate_variables("uuid")
    token = setup_rogue(nf_instance_id, nf_type="AMF", scope="nudm-sdm")
    url   = ip + uri

    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}"  
    }

    with httpx.Client(http1=False,http2=True, verify=False) as client:

        # Send the request to the target server
        if method in ["GET", "DELETE"]:
            if data : 
                query_string = urllib.parse.urlencode(data, doseq=True)
                url += f"?{query_string}"
            response = client.request(method, url, headers=headers)
        elif method == "POST":
            response = client.request(method, url, data=data, headers=headers)
        else :
            response = client.request(method, url, json=data, headers=headers)
        
    return response.status_code, response.content
        
if __name__ == '__main__':
    victim_request()