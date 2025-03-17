from . import generate_variables
import httpx
import yaml
import urllib.parse

# Get the IP list of the CN components
file_path = "./src/const/plateform_free5gc.yaml"
with open(file_path, 'r', encoding='utf-8') as file:
    ip_list = yaml.safe_load(file)["addresses"]

def request_cn(nf,data,method,uri,headers={},token="",display=True):

    url = f"http://{ip_list[nf]}:8000" + uri

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

        if method in ["GET", "DELETE"]:
            if data : 
                query_string = urllib.parse.urlencode(data, doseq=True)
                url += f"?{query_string}"
            response = client.request(method, url, headers=base_headers)
        elif method == "POST":
            response = client.request(method, url, data=data, headers=base_headers)
        else :
            response = client.request(method, url, json=data, headers=base_headers)

    try    : result = response.json()
    except : result = response.text

    # Afficher la réponse
    if display : 
        print(f"Request {method} {url}")
        if headers : print(f"-> Headers : {headers}")
        if data    : print(f"-> Body : {data}")
        print(f"-> Status Code {response.status_code}")
        print(result)

    return response.status_code, result

# OK
def ping_nf(nf, display=True):
    return request_cn(nf, {}, "GET","", display=display)

# OK
def add_nf(nf_instance_id, nf_type, display=True):
    data = {
        "nfInstanceId": nf_instance_id,
        "nfType": nf_type,
        "nfStatus": "REGISTERED"
    }
    return request_cn(
        "NRF", data, "PUT",
        f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}",
        display=display
    )

# OK
def remove_nf(nf_instance_id, token, display=True):
    # curl -s -o /dev/null -w "\n\nHTTP Status Code: %{http_code}\n\n" -X DELETE http://127.0.0.10:8000/nnrf-nfm/v1/nf-instances/$fakeAMF
    uri = f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}"
    return request_cn("NRF", {}, "DELETE", uri, token=token,display=display)

# OK
def get_token(nf_instance_id, nf_type, scope, target_type, display=True):
    data = {
        "grant_type": "client_credentials",
        "nfInstanceId": nf_instance_id,
        "nfType": nf_type,
        "scope": scope,
        "targetNfType" : target_type
    }
    status, token = request_cn("NRF", data, "POST", f"/oauth2/token", display=display)
    return token["access_token"]

# OK
def setup_rogue(nf_instance_id=generate_variables("uuid"), nf_type = "AMF", scope="nnrf-disc", target_type = "NRF"):
    add_nf(nf_instance_id, nf_type, display=False)
    return get_token(nf_instance_id, nf_type, scope, target_type, display=False)